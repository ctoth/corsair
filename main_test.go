package main

import (
	"bytes"
	"context"
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
		w.Header().Set("Cache-Control", "max-age=60") // only fresh responses are cached
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

// seekableMedia is a 100-byte resource served with http.ServeContent, which
// implements Range, suffix ranges, 416, HEAD and If-Range like a real origin.
const seekableMedia = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" + "!@#$%^&*()-_=+[]{};:,.<>/?|~0123456789"

type seenRequest struct {
	method         string
	rangeHeader    string
	acceptEncoding string
}

func newSeekableOrigin(t *testing.T, contentType string, cacheControl string) (*httptest.Server, func() []seenRequest) {
	t.Helper()
	if len(seekableMedia) != 100 {
		t.Fatalf("fixture length = %d", len(seekableMedia))
	}
	var mu sync.Mutex
	var seen []seenRequest
	modTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Direct") == "" { // record only proxied requests
			mu.Lock()
			seen = append(seen, seenRequest{r.Method, r.Header.Get("Range"), r.Header.Get("Accept-Encoding")})
			mu.Unlock()
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", `"media-v1"`)
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		http.ServeContent(w, r, "media", modTime, strings.NewReader(seekableMedia))
	}))
	return server, func() []seenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenRequest(nil), seen...)
	}
}

func doProxy(t *testing.T, proxy *httptest.Server, method, target string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, proxiedURL(proxy.URL, target), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %v failed: %v", method, headers, err)
	}
	return resp, readResponseBody(t, resp)
}

func TestRangeRequestsPassThroughExactly(t *testing.T) {
	resetProxyState(t)

	origin, seen := newSeekableOrigin(t, "audio/mp4", "")
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	target := origin.URL + "/buzz1.m4a"

	type want struct {
		status       int
		contentRange string
		length       string
		body         string
	}
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    want
	}{
		{"first 64 bytes", "GET", map[string]string{"Range": "bytes=0-63"},
			want{206, "bytes 0-63/100", "64", seekableMedia[:64]}},
		{"suffix range", "GET", map[string]string{"Range": "bytes=-10"},
			want{206, "bytes 90-99/100", "10", seekableMedia[90:]}},
		{"unsatisfiable", "GET", map[string]string{"Range": "bytes=100-"},
			want{416, "bytes */100", "", ""}},
		{"HEAD", "HEAD", nil,
			want{200, "", "100", ""}},
		{"If-Range matches", "GET", map[string]string{"Range": "bytes=10-19", "If-Range": `"media-v1"`},
			want{206, "bytes 10-19/100", "10", seekableMedia[10:20]}},
		{"If-Range stale", "GET", map[string]string{"Range": "bytes=10-19", "If-Range": `"media-v0"`},
			want{200, "", "100", seekableMedia}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := doProxy(t, proxy, tc.method, target, tc.headers)
			if resp.StatusCode != tc.want.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want.status)
			}
			assertHeader(t, resp.Header, "Content-Range", tc.want.contentRange)
			if tc.want.length != "" {
				assertHeader(t, resp.Header, "Content-Length", tc.want.length)
			}
			wantBody := tc.want.body
			if tc.want.status == http.StatusRequestedRangeNotSatisfiable {
				// The 416 body is the origin's; compare it with a direct fetch.
				directReq, _ := http.NewRequest(tc.method, target, nil)
				for k, v := range tc.headers {
					directReq.Header.Set(k, v)
				}
				directReq.Header.Set("X-Test-Direct", "1")
				directResp, err := origin.Client().Do(directReq)
				if err != nil {
					t.Fatalf("direct request failed: %v", err)
				}
				wantBody = readResponseBody(t, directResp)
			}
			if body != wantBody {
				t.Fatalf("body = %q, want %q", body, wantBody)
			}
			if tc.want.status != 416 {
				assertHeader(t, resp.Header, "Accept-Ranges", "bytes")
				assertHeader(t, resp.Header, "ETag", `"media-v1"`)
			}
			assertCorsPolicy(t, resp.Header)
		})
	}

	for _, req := range seen() {
		if req.rangeHeader != "" && req.acceptEncoding != "identity" {
			t.Fatalf("range request %+v reached origin with Accept-Encoding %q, want identity", req, req.acceptEncoding)
		}
	}
	if got := seen(); len(got) != len(cases) || got[3].method != "HEAD" {
		t.Fatalf("origin saw %+v", got)
	}
}

func TestFullAndPartialResponsesDoNotPoisonEachOther(t *testing.T) {
	resetProxyState(t)

	// Cacheable by every rule except the range: a full 200 may be cached, but
	// it must never answer a later range request, and vice versa.
	origin, seen := newSeekableOrigin(t, "application/octet-stream", "max-age=60")
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	target := origin.URL + "/blob.bin"

	resp, body := doProxy(t, proxy, "GET", target, nil)
	if resp.StatusCode != 200 || body != seekableMedia {
		t.Fatalf("full: status = %d body = %q", resp.StatusCode, body)
	}
	resp, body = doProxy(t, proxy, "GET", target, map[string]string{"Range": "bytes=0-9"})
	if resp.StatusCode != 206 || body != seekableMedia[:10] {
		t.Fatalf("range after full: status = %d body = %q", resp.StatusCode, body)
	}
	assertHeader(t, resp.Header, "Content-Range", "bytes 0-9/100")
	resp, body = doProxy(t, proxy, "GET", target, nil)
	if resp.StatusCode != 200 || body != seekableMedia {
		t.Fatalf("full after range: status = %d body = %q", resp.StatusCode, body)
	}
	assertHeader(t, resp.Header, "Content-Range", "")

	if got := seen(); len(got) != 2 || got[1].rangeHeader != "bytes=0-9" {
		t.Fatalf("origin saw %+v, want the full fetch and the range fetch only", got)
	}
}

func TestClientDisconnectCancelsUpstreamRequest(t *testing.T) {
	resetProxyState(t)

	upstreamCancelled := make(chan struct{})
	testDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(upstreamCancelled)
		case <-testDone:
		}
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	defer close(testDone) // runs before the servers' Close, which wait for handlers

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", proxiedURL(proxy.URL, upstream.URL+"/live.mp3"), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	first := make([]byte, len("first"))
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first chunk = %q, err = %v", first, err)
	}

	cancel()

	select {
	case <-upstreamCancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not cancelled after the client disconnected")
	}
}

func TestFlushingSourceReachesClientBeforeSourceCloses(t *testing.T) {
	resetProxyState(t)

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		io.WriteString(w, "first-chunk")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "-rest")
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	defer releaseUpstream() // runs before the servers' Close, which wait for handlers

	type result struct {
		resp *http.Response
		data string
		err  error
	}
	firstChunk := make(chan result, 1)
	go func() {
		resp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/live.mp3"))
		if err != nil {
			firstChunk <- result{err: err}
			return
		}
		buf := make([]byte, len("first-chunk"))
		_, err = io.ReadFull(resp.Body, buf)
		firstChunk <- result{resp: resp, data: string(buf), err: err}
	}()

	var got result
	select {
	case got = <-firstChunk:
	case <-time.After(2 * time.Second):
		releaseUpstream()
		t.Fatal("first chunk did not arrive while the source was still open")
	}
	if got.err != nil || got.data != "first-chunk" {
		t.Fatalf("first chunk = %q, err = %v", got.data, got.err)
	}

	releaseUpstream()
	if rest := readResponseBody(t, got.resp); rest != "-rest" {
		t.Fatalf("remaining body = %q", rest)
	}
}

func TestLiveStreamOutlivesResponseHeaderTimeout(t *testing.T) {
	configureForTest(t, "*", 1) // one-second upstream timeout

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		flusher := w.(http.Flusher)
		for i := 0; i < 6; i++ {
			fmt.Fprintf(w, "chunk%d;", i)
			flusher.Flush()
			time.Sleep(250 * time.Millisecond)
		}
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/radio.mp3"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("stream broke after %q: %v", body, err)
	}
	if want := "chunk0;chunk1;chunk2;chunk3;chunk4;chunk5;"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestHopByHopHeadersAreNotForwarded(t *testing.T) {
	resetProxyState(t)

	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Connection", "X-Hop-Resp")
		w.Header().Set("X-Hop-Resp", "1")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Proxy-Authenticate", "Basic")
		w.Header().Set("X-End-To-End", "resp")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, body := doProxy(t, proxy, "GET", upstream.URL+"/x", map[string]string{
		"Connection":          "X-Hop-Req",
		"X-Hop-Req":           "1",
		"Keep-Alive":          "timeout=5",
		"Proxy-Authorization": "Basic c2VjcmV0",
		"X-End-To-End":        "req",
	})
	if body != "ok" {
		t.Fatalf("body = %q", body)
	}

	for _, name := range []string{"X-Hop-Req", "Keep-Alive", "Proxy-Authorization"} {
		if v := upstreamHeaders.Get(name); v != "" {
			t.Errorf("request hop-by-hop header %s reached upstream: %q", name, v)
		}
	}
	if strings.Contains(upstreamHeaders.Get("Connection"), "X-Hop-Req") {
		t.Errorf("request Connection tokens reached upstream: %q", upstreamHeaders.Get("Connection"))
	}
	assertHeader(t, upstreamHeaders, "X-End-To-End", "req")

	for _, name := range []string{"X-Hop-Resp", "Keep-Alive", "Proxy-Authenticate"} {
		if v := resp.Header.Get(name); v != "" {
			t.Errorf("response hop-by-hop header %s reached client: %q", name, v)
		}
	}
	assertHeader(t, resp.Header, "X-End-To-End", "resp")
}

func TestRequestContentLengthIsNotEchoedAsResponseLength(t *testing.T) {
	resetProxyState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "received %q", got)
		w.(http.Flusher).Flush() // force a length-less (chunked) response
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, err := proxy.Client().Post(proxiedURL(proxy.URL, upstream.URL+"/echo"), "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	body := readResponseBody(t, resp)
	if body != `received "hello"` {
		t.Fatalf("body = %q", body)
	}
	if cl := resp.Header.Get("Content-Length"); cl == "5" {
		t.Fatalf("response echoed the request Content-Length")
	}
}

func TestUpstreamFailureAfterHeadersAbortsTheResponse(t *testing.T) {
	cases := []struct {
		name          string
		declaredBytes string
	}{
		{name: "chunked", declaredBytes: ""},
		{name: "known length", declaredBytes: "100"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetProxyState(t)

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				if tc.declaredBytes != "" {
					w.Header().Set("Content-Length", tc.declaredBytes)
				}
				io.WriteString(w, "partial")
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			}))
			defer upstream.Close()
			proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
			defer proxy.Close()

			resp, err := proxy.Client().Get(proxiedURL(proxy.URL, upstream.URL+"/file.bin"))
			if err != nil {
				t.Fatalf("request failed before headers: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				t.Fatalf("truncated upstream body %q ended cleanly; the proxy must abort the connection", body)
			}
			if string(body) != "partial" {
				t.Fatalf("body = %q, want only the upstream bytes", body)
			}
		})
	}
}

func TestTruncatedCacheableBodyIsA502AndNotCached(t *testing.T) {
	resetProxyState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	resp, body := doProxy(t, proxy, "GET", upstream.URL+"/data.json", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d body = %q, want 502", resp.StatusCode, body)
	}
	if entries, bytes := cache.stats(); entries != 0 || bytes != 0 {
		t.Fatalf("cache holds %d entries / %d bytes, want none", entries, bytes)
	}
}

// setClock pins the proxy's clock for cache-freshness tests.
func setClock(t *testing.T, at *time.Time) {
	t.Helper()
	nowFunc = func() time.Time { return *at }
	t.Cleanup(func() { nowFunc = time.Now })
}

// countingOrigin serves body with the given headers and counts requests.
func countingOrigin(body string, headers map[string]string) (*httptest.Server, *int32) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		io.WriteString(w, body)
	}))
	return server, &hits
}

func fetchTwice(t *testing.T, proxy *httptest.Server, target, wantBody string) {
	t.Helper()
	for i := 0; i < 2; i++ {
		resp, body := doProxy(t, proxy, "GET", target, nil)
		if resp.StatusCode != http.StatusOK || body != wantBody {
			t.Fatalf("fetch %d: status = %d, body length %d, want %d", i, resp.StatusCode, len(body), len(wantBody))
		}
	}
}

func TestResponsesWithoutFreshnessAreNotCached(t *testing.T) {
	resetProxyState(t)

	origin, hits := countingOrigin("feed", map[string]string{"Content-Type": "application/rss+xml", "ETag": `"x"`})
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	fetchTwice(t, proxy, origin.URL+"/feed.xml", "feed")
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (no max-age/Expires means no caching)", got)
	}
	if entries, bytes := cache.stats(); entries != 0 || bytes != 0 {
		t.Fatalf("cache holds %d entries / %d bytes, want none", entries, bytes)
	}
}

func TestCachedEntryExpiresAndRevalidatesWith304Merge(t *testing.T) {
	resetProxyState(t)
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	setClock(t, &clock)

	var hits int32
	var lastIfNoneMatch atomic.Value
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		lastIfNoneMatch.Store(r.Header.Get("If-None-Match"))
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.Header().Set("X-Revision", "2")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("X-Revision", "1")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "9")
		io.WriteString(w, `{"a":"b"}`)
	}))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	target := origin.URL + "/data.json"

	expect := func(step string, advance time.Duration, headers map[string]string, status int, body, revision string, wantHits int32) {
		t.Helper()
		clock = clock.Add(advance)
		resp, got := doProxy(t, proxy, "GET", target, headers)
		if resp.StatusCode != status || got != body {
			t.Fatalf("%s: status = %d body = %q, want %d %q", step, resp.StatusCode, got, status, body)
		}
		if got := resp.Header.Get("X-Revision"); got != revision {
			t.Fatalf("%s: X-Revision = %q, want %q (origin hits %d)", step, got, revision, atomic.LoadInt32(&hits))
		}
		if h := atomic.LoadInt32(&hits); h != wantHits {
			t.Fatalf("%s: origin hits = %d, want %d", step, h, wantHits)
		}
	}

	expect("initial fetch", 0, nil, 200, `{"a":"b"}`, "1", 1)
	expect("fresh hit", 30*time.Second, nil, 200, `{"a":"b"}`, "1", 1)
	expect("fresh conditional hit", 0, map[string]string{"If-None-Match": `"v1"`}, 304, "", "1", 1)

	expect("stale revalidation", 31*time.Second, nil, 200, `{"a":"b"}`, "2", 2)
	if got := lastIfNoneMatch.Load(); got != `"v1"` {
		t.Fatalf("revalidation sent If-None-Match %q, want the stored ETag", got)
	}
	expect("fresh after revalidation", 59*time.Second, nil, 200, `{"a":"b"}`, "2", 2)
	expect("stale again", 2*time.Second, nil, 200, `{"a":"b"}`, "2", 3)
}

func TestExpiresHeaderBoundsFreshness(t *testing.T) {
	resetProxyState(t)
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	setClock(t, &clock)

	origin, hits := countingOrigin("expiring", map[string]string{
		"Content-Type": "text/plain",
		"Date":         clock.Format(http.TimeFormat),
		"Expires":      clock.Add(30 * time.Second).Format(http.TimeFormat),
	})
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	target := origin.URL + "/e.txt"

	fetchTwice(t, proxy, target, "expiring")
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("origin hits = %d, want 1 while fresh", got)
	}
	clock = clock.Add(31 * time.Second)
	fetchTwice(t, proxy, target, "expiring")
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("origin hits = %d, want 2 after expiry", got)
	}
}

func TestOversizedResponsesStreamWithoutCaching(t *testing.T) {
	resetProxyState(t)

	big := strings.Repeat("x", maxCacheEntryBytes+1)
	origin, hits := countingOrigin(big, map[string]string{"Content-Type": "application/octet-stream", "Cache-Control": "max-age=60"})
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()

	fetchTwice(t, proxy, origin.URL+"/big.bin", big)
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("origin hits = %d, want 2", got)
	}
	if entries, bytes := cache.stats(); entries != 0 || bytes != 0 {
		t.Fatalf("cache holds %d entries / %d bytes, want none", entries, bytes)
	}
}

func TestMediaAndManifestsBypassTheCache(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		contentType string
	}{
		{"audio", "/a.mp3", "audio/mpeg"},
		{"video", "/v.mp4", "video/mp4"},
		{"HLS manifest", "/list", "application/vnd.apple.mpegurl"},
		{"HLS manifest x-", "/list", "application/x-mpegURL"},
		{"DASH manifest", "/list", "application/dash+xml"},
		{"m3u8 by path", "/live/index.m3u8", "text/plain"},
		{"mpd by path", "/live/manifest.mpd", "application/xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetProxyState(t)
			origin, hits := countingOrigin("#EXTM3U", map[string]string{"Content-Type": tc.contentType, "Cache-Control": "max-age=60"})
			defer origin.Close()
			proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
			defer proxy.Close()

			fetchTwice(t, proxy, origin.URL+tc.path, "#EXTM3U")
			if got := atomic.LoadInt32(hits); got != 2 {
				t.Fatalf("origin hits = %d, want 2", got)
			}
		})
	}
}

func TestIfRangeRequestsBypassTheCache(t *testing.T) {
	resetProxyState(t)

	origin, hits := countingOrigin("document", map[string]string{"Content-Type": "text/plain", "Cache-Control": "max-age=60", "ETag": `"d1"`})
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(proxyHandler))
	defer proxy.Close()
	target := origin.URL + "/doc.txt"

	doProxy(t, proxy, "GET", target, nil)
	resp, body := doProxy(t, proxy, "GET", target, map[string]string{"If-Range": `"d1"`})
	if resp.StatusCode != 200 || body != "document" {
		t.Fatalf("status = %d body = %q", resp.StatusCode, body)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (If-Range must not be answered from cache)", got)
	}
}

func TestResponseCacheByteAccounting(t *testing.T) {
	c, err := newResponseCache(3, 10, 6)
	if err != nil {
		t.Fatalf("newResponseCache: %v", err)
	}
	entry := func(n int) *cacheEntry { return &cacheEntry{content: []byte(strings.Repeat("z", n))} }
	expectStats := func(step string, wantEntries int, wantBytes int64) {
		t.Helper()
		if entries, bytes := c.stats(); entries != wantEntries || bytes != wantBytes {
			t.Fatalf("%s: %d entries / %d bytes, want %d / %d", step, entries, bytes, wantEntries, wantBytes)
		}
	}

	c.add("a", entry(4))
	c.add("b", entry(4))
	expectStats("two entries", 2, 8)

	c.add("c", entry(4)) // 12 bytes > 10: evict the oldest ("a")
	expectStats("byte cap", 2, 8)
	if _, ok := c.get("a"); ok {
		t.Fatal("oldest entry survived the byte cap")
	}

	if c.add("big", entry(7)) {
		t.Fatal("entry above the per-entry cap was stored")
	}
	expectStats("per-entry cap", 2, 8)

	c.add("b", entry(2)) // replacement re-accounts the key
	expectStats("replacement", 2, 6)

	c.add("d", entry(1))
	c.add("e", entry(1)) // four keys > 3 entries: evict the least recent ("c")
	expectStats("entry cap", 3, 4)
	if _, ok := c.get("c"); ok {
		t.Fatal("least recently used entry survived the entry cap")
	}

	c.remove("b")
	expectStats("remove", 2, 2)
}

func TestConfiguredCacheLimits(t *testing.T) {
	resetProxyState(t)
	if maxCacheEntryBytes != 1<<20 || maxCacheBytes != 32<<20 {
		t.Fatalf("limits = %d per entry / %d total, want 1 MiB / 32 MiB", maxCacheEntryBytes, maxCacheBytes)
	}
	if cache.maxEntries != 100 || cache.maxBytes != maxCacheBytes || cache.maxEntryBytes != maxCacheEntryBytes {
		t.Fatalf("configured cache = %d entries / %d bytes / %d per entry", cache.maxEntries, cache.maxBytes, cache.maxEntryBytes)
	}
}
