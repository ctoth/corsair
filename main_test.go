package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetProxyState rebuilds the proxy's global state through configure, so
// tests exercise the same client, redirect policy and cache as production.
func resetProxyState(t *testing.T) {
	t.Helper()
	configureForTest(t, "*", 5)
}

func configureForTest(t *testing.T, domainList string, timeoutSeconds int) {
	t.Helper()
	shoVersion = false
	domains = domainList
	timeout = timeoutSeconds
	cacheSize = 100
	configure()
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

const (
	wantAllowMethods  = "GET, HEAD, POST, OPTIONS"
	wantAllowHeaders  = "Content-Type, Range, If-Range, If-None-Match, If-Modified-Since"
	wantExposeHeaders = "Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified, Content-Type"
)

func assertHeader(t *testing.T, h http.Header, name, want string) {
	t.Helper()
	if got := h.Get(name); got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func assertCorsPolicy(t *testing.T, h http.Header) {
	t.Helper()
	assertHeader(t, h, "Access-Control-Allow-Origin", "*")
	assertHeader(t, h, "Access-Control-Allow-Methods", wantAllowMethods)
	assertHeader(t, h, "Access-Control-Allow-Headers", wantAllowHeaders)
	assertHeader(t, h, "Access-Control-Expose-Headers", wantExposeHeaders)
}

func TestPreflightAllowsRangeWithoutContactingUpstream(t *testing.T) {
	resetProxyState(t)

	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	req, err := http.NewRequest("OPTIONS", proxiedURL(proxy.URL, upstream.URL+"/buzz1.m4a"), nil)
	if err != nil {
		t.Fatalf("failed to create preflight: %v", err)
	}
	req.Header.Set("Origin", "https://mongoose.world")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "range,if-range")
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	if body := readResponseBody(t, resp); body != "" {
		t.Fatalf("preflight body = %q", body)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preflight status = %d", resp.StatusCode)
	}
	assertCorsPolicy(t, resp.Header)
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

func TestUpstreamCorsHeadersDoNotOverrideProxyPolicy(t *testing.T) {
	resetProxyState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://evil.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "X-Upstream-Only")
		w.Header().Set("Access-Control-Allow-Methods", "DELETE")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "hello")
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/x"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if body := readResponseBody(t, resp); body != "hello" {
		t.Fatalf("body = %q", body)
	}
	assertCorsPolicy(t, resp.Header)
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("upstream Access-Control-Allow-Credentials leaked: %q", got)
	}
}

func TestParseTargetURLRequiresAbsoluteHTTPURLWithHost(t *testing.T) {
	cases := []struct {
		raw  string
		ok   bool
		want string
	}{
		{raw: "https://mongoose.world/sounds/a.m4a?x=1", ok: true, want: "https://mongoose.world/sounds/a.m4a?x=1"},
		{raw: "http://example.com", ok: true, want: "http://example.com"},
		{raw: "HTTPS://Example.com/a", ok: true, want: "https://Example.com/a"},
		{raw: ""},
		{raw: "/relative/path"},
		{raw: "example.com/no-scheme"},
		{raw: "ftp://example.com/file"},
		{raw: "file:///etc/passwd"},
		{raw: "javascript:alert(1)"},
		{raw: "http://"},
		{raw: "http:///path-only"},
		{raw: "https://user:pass@example.com/"},
		{raw: "http://%zz"},
	}
	for _, tc := range cases {
		got, err := parseTargetURL(url.Values{"url": {tc.raw}})
		if tc.ok {
			if err != nil {
				t.Errorf("parseTargetURL(%q) error = %v", tc.raw, err)
			} else if got.String() != tc.want {
				t.Errorf("parseTargetURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseTargetURL(%q) = %q, want error", tc.raw, got)
		}
		if strings.Contains(fmt.Sprint(err), "pass@") {
			t.Errorf("parseTargetURL(%q) error leaks credentials: %v", tc.raw, err)
		}
	}
}

func TestInvalidTargetIsRejectedWithoutUpstreamRequest(t *testing.T) {
	resetProxyState(t)

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, err := proxy.Client().Get(proxy.URL + "/?url=" + url.QueryEscape("file:///etc/passwd"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	readResponseBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	assertHeader(t, resp.Header, "Access-Control-Allow-Origin", "*")
}

// redirectChain serves /hop/N, redirecting to /hop/N+1 until N reaches total.
func redirectChain(total int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if n < total {
			http.Redirect(w, r, fmt.Sprintf("/hop/%d", n+1), http.StatusFound)
			return
		}
		fmt.Fprint(w, "arrived")
	}))
}

func TestRedirectsAreCappedAtTen(t *testing.T) {
	resetProxyState(t)

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	tenHops := redirectChain(10)
	defer tenHops.Close()
	resp, err := proxy.Client().Get(proxiedURL(proxy.URL, tenHops.URL+"/hop/0"))
	if err != nil {
		t.Fatalf("ten-hop request failed: %v", err)
	}
	if body := readResponseBody(t, resp); resp.StatusCode != http.StatusOK || body != "arrived" {
		t.Fatalf("ten hops: status = %d body = %q", resp.StatusCode, body)
	}

	elevenHops := redirectChain(11)
	defer elevenHops.Close()
	resp, err = proxy.Client().Get(proxiedURL(proxy.URL, elevenHops.URL+"/hop/0"))
	if err != nil {
		t.Fatalf("eleven-hop request failed: %v", err)
	}
	body := readResponseBody(t, resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("eleven hops: status = %d body = %q, want 502", resp.StatusCode, body)
	}
}

func TestRedirectToDisallowedDomainIsRejected(t *testing.T) {
	configureForTest(t, "127.0.0.1", 5)

	var forbiddenHits int32
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&forbiddenHits, 1)
		fmt.Fprint(w, "should not be reached")
	}))
	defer forbidden.Close()
	forbiddenURL, err := url.Parse(forbidden.URL)
	if err != nil {
		t.Fatalf("parse forbidden URL: %v", err)
	}

	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+forbiddenURL.Port()+"/secret", http.StatusFound)
	}))
	defer allowed.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, err := proxy.Client().Get(proxiedURL(proxy.URL, allowed.URL+"/start"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body := readResponseBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d body = %q, want 403", resp.StatusCode, body)
	}
	if hits := atomic.LoadInt32(&forbiddenHits); hits != 0 {
		t.Fatalf("disallowed redirect target was contacted %d times", hits)
	}
}

func TestQueryStringsAreRedactedFromErrorsAndLogs(t *testing.T) {
	resetProxyState(t)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			panic(http.ErrAbortHandler) // drop the connection without a response
		}
		w.Header().Set("Content-Type", "audio/mpeg")
		fmt.Fprint(w, "audio")
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/broken?sig=topsecret"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body := readResponseBody(t, resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d body = %q, want 502", resp.StatusCode, body)
	}
	if strings.Contains(body, "topsecret") {
		t.Fatalf("error body leaks query: %q", body)
	}

	resp, err = proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/ok.mp3?sig=topsecret"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if body := readResponseBody(t, resp); body != "audio" {
		t.Fatalf("body = %q", body)
	}

	if strings.Contains(logs.String(), "topsecret") {
		t.Fatalf("logs leak query: %q", logs.String())
	}
}
