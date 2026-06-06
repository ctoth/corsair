package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

func resetProxyState(t *testing.T) {
	t.Helper()

	testCache, err := lru.New(100)
	if err != nil {
		t.Fatalf("failed to create test cache: %v", err)
	}

	cacheMutex.Lock()
	cache = testCache
	cacheMutex.Unlock()

	allowAllDomains = true
	allowedDomains = map[string]bool{}
	client = &http.Client{Timeout: 5 * time.Second}
}

func proxiedURL(proxyURL, targetURL string) string {
	return proxyURL + "/?url=" + url.QueryEscape(targetURL)
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	return string(body)
}

func TestAuthenticatedGETsAreNotSharedThroughCache(t *testing.T) {
	resetProxyState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "feed for " + r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		fmt.Fprint(w, body)
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	firstReq, err := http.NewRequest("GET", proxiedURL(proxy.URL, upstream.URL+"/feed.xml"), nil)
	if err != nil {
		t.Fatalf("failed to create first request: %v", err)
	}
	firstReq.Header.Set("Authorization", "Bearer first")
	firstResp, err := proxy.Client().Do(firstReq)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if body := readResponseBody(t, firstResp); body != "feed for Bearer first" {
		t.Fatalf("first response body = %q", body)
	}

	secondReq, err := http.NewRequest("GET", proxiedURL(proxy.URL, upstream.URL+"/feed.xml"), nil)
	if err != nil {
		t.Fatalf("failed to create second request: %v", err)
	}
	secondReq.Header.Set("Authorization", "Bearer second")
	secondResp, err := proxy.Client().Do(secondReq)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if body := readResponseBody(t, secondResp); body != "feed for Bearer second" {
		t.Fatalf("second response body = %q", body)
	}
}

func TestRangeResponseDoesNotPoisonFullURLCache(t *testing.T) {
	resetProxyState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			body := "abc"
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-2/6")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			fmt.Fprint(w, body)
			return
		}

		body := "abcdef"
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		fmt.Fprint(w, body)
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	rangeReq, err := http.NewRequest("GET", proxiedURL(proxy.URL, upstream.URL+"/episode.mp3"), nil)
	if err != nil {
		t.Fatalf("failed to create range request: %v", err)
	}
	rangeReq.Header.Set("Range", "bytes=0-2")
	rangeResp, err := proxy.Client().Do(rangeReq)
	if err != nil {
		t.Fatalf("range request failed: %v", err)
	}
	if rangeResp.StatusCode != http.StatusPartialContent {
		t.Fatalf("range status = %d", rangeResp.StatusCode)
	}
	if body := readResponseBody(t, rangeResp); body != "abc" {
		t.Fatalf("range response body = %q", body)
	}

	fullResp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/episode.mp3"))
	if err != nil {
		t.Fatalf("full request failed: %v", err)
	}
	if fullResp.StatusCode != http.StatusOK {
		t.Fatalf("full status = %d", fullResp.StatusCode)
	}
	if body := readResponseBody(t, fullResp); body != "abcdef" {
		t.Fatalf("full response body = %q", body)
	}
}

func TestCachedPodcastFeedPreservesResponseHeaders(t *testing.T) {
	resetProxyState(t)

	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		body := "<rss><channel><title>Test</title></channel></rss>"
		w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("ETag", `"feed-v1"`)
		fmt.Fprint(w, body)
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	target := proxiedURL(proxy.URL, upstream.URL+"/feed.xml")
	firstResp, err := proxy.Client().Get(target)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	readResponseBody(t, firstResp)

	secondResp, err := proxy.Client().Get(target)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if contentType := secondResp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/rss+xml") {
		t.Fatalf("cached content type = %q", contentType)
	}
	if etag := secondResp.Header.Get("ETag"); etag != `"feed-v1"` {
		t.Fatalf("cached etag = %q", etag)
	}
	if body := readResponseBody(t, secondResp); body != "<rss><channel><title>Test</title></channel></rss>" {
		t.Fatalf("cached body = %q", body)
	}
	if hits := atomic.LoadInt32(&upstreamHits); hits != 1 {
		t.Fatalf("upstream hits = %d", hits)
	}
}

func TestConcurrentAudioRequestsStreamIndependently(t *testing.T) {
	resetProxyState(t)

	const requestCount = 5
	const audioBody = "ID3-audio-chunk-1-audio-chunk-2"

	var active int32
	var maxActive int32
	var started int32
	var releaseOnce sync.Once
	release := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&active, 1)
		defer atomic.AddInt32(&active, -1)

		for {
			previousMax := atomic.LoadInt32(&maxActive)
			if current <= previousMax || atomic.CompareAndSwapInt32(&maxActive, previousMax, current) {
				break
			}
		}

		if atomic.AddInt32(&started, 1) == requestCount {
			releaseOnce.Do(func() { close(release) })
		}

		select {
		case <-release:
		case <-time.After(2 * time.Second):
			t.Errorf("timed out waiting for concurrent audio requests")
			return
		}

		w.Header().Set("Content-Type", "audio/mpeg")
		flusher, _ := w.(http.Flusher)
		for _, chunk := range []string{"ID3-audio-", "chunk-1-", "audio-chunk-2"} {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	var wg sync.WaitGroup
	errs := make(chan error, requestCount)
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			resp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/episode.mp3"))
			if err != nil {
				errs <- err
				return
			}
			body := readResponseBody(t, resp)
			if body != audioBody {
				errs <- fmt.Errorf("audio body = %q", body)
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if max := atomic.LoadInt32(&maxActive); max < 2 {
		t.Fatalf("audio requests did not overlap; max active = %d", max)
	}
}
