package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	Version         = "dev"
	GitCommit       = "none"
	BuildDate       = "unknown"
	shoVersion      bool
	port            int
	listenAddr      string
	domains         string
	allowedDomains  map[string]bool
	allowAllDomains bool
	timeout         int
	clientTimeout   time.Duration
	cacheSize       int
	client          *http.Client
	cache           *lru.Cache
	cacheMutex      sync.RWMutex
)

var (
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "corsair_requests_total",
			Help: "Total number of processed requests.",
		},
		[]string{"method", "endpoint"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "corsair_request_duration_seconds",
			Help: "Histogram of request durations.",
		},
		[]string{"endpoint"},
	)
	cacheHitCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "corsair_cache_hits_total",
			Help: "Total number of cache hits.",
		},
	)
	cacheMissCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "corsair_cache_misses_total",
			Help: "Total number of cache misses.",
		},
	)
)

type cacheEntry struct {
	content      []byte
	headers      http.Header
	statusCode   int
	etag         string
	lastModified string
}

func init() {
	flag.BoolVar(&shoVersion, "version", false, "Show version information")
	flag.IntVar(&port, "port", getEnvAsInt("CORSAIR_PORT", 8080), "Port to run the proxy server on")
	flag.StringVar(&listenAddr, "interface", getEnv("CORSAIR_INTERFACE", "localhost"), "Network interface to listen on")
	flag.StringVar(&domains, "domains", getEnv("CORSAIR_DOMAINS", "*"), "Comma-separated list of allowed domains for forwarding, default to '*' for all")
	flag.IntVar(&timeout, "timeout", getEnvAsInt("CORSAIR_TIMEOUT", 0), "Seconds to wait for upstream response headers (0 = no limit); streamed bodies have no total deadline")
	flag.IntVar(&cacheSize, "cache-size", getEnvAsInt("CORSAIR_CACHE_SIZE", 100), "Size of the cache")

	prometheus.MustRegister(requestCounter, requestDuration, cacheHitCounter, cacheMissCounter)
}

func main() {
	flag.Parse()
	configure()
	http.HandleFunc("/", proxyHandler)
	http.HandleFunc("/health", healthCheckHandler)
	http.HandleFunc("/favicon.ico", faviconHandler) // New handler for favicon.ico
	http.Handle("/metrics", promhttp.Handler())
	address := fmt.Sprintf("%s:%d", listenAddr, port)
	log.Printf("Proxy server started on %s\n", address)
	log.Fatal(http.ListenAndServe(address, nil))
}

func configure() {
	if shoVersion {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Git commit: %s\n", GitCommit)
		fmt.Printf("Build date: %s\n", BuildDate)

		os.Exit(0)
	}

	if cacheSize < 1 {
		log.Fatalf("Invalid cache size: %d", cacheSize)
	}

	allowedDomains = make(map[string]bool)
	allowAllDomains = false
	if domains == "*" {
		allowAllDomains = true
	} else {
		for _, domain := range strings.Split(domains, ",") {
			if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
				allowedDomains[domain] = true
			}
		}
	}

	var err error
	cache, err = lru.New(cacheSize)
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	clientTimeout = time.Duration(timeout) * time.Second
	client = newUpstreamClient(clientTimeout)
}

// newUpstreamClient builds the origin client. Live sources have no total body
// deadline: the connection, TLS handshake and response headers are bounded,
// and the request context ends the body when the client leaves. A zero
// responseHeaderTimeout waits for headers indefinitely.
func newUpstreamClient(responseHeaderTimeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
		// Relay the origin's bytes untouched; transparent decompression
		// would change lengths and byte-range coordinates.
		DisableCompression: true,
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}
}

// maxRedirects is the number of redirects the proxy follows for one request.
const maxRedirects = 10

var (
	errTooManyRedirects   = fmt.Errorf("stopped after %d redirects", maxRedirects)
	errRedirectNotAllowed = errors.New("redirect target is not allowed")
)

// checkRedirect caps redirect chains and re-applies the target rules (scheme,
// host and domain allowlist) to every hop, so a redirect cannot reach a target
// the proxy would refuse if it were requested directly.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errTooManyRedirects
	}
	if validateTarget(req.URL) != nil || !isDomainAllowed(req.URL) {
		return errRedirectNotAllowed
	}
	return nil
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// faviconHandler responds to /favicon.ico requests
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent) // Respond with 204 No Content
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	timer := prometheus.NewTimer(requestDuration.WithLabelValues(r.URL.Path))
	defer timer.ObserveDuration()

	requestCounter.WithLabelValues(r.Method, r.URL.Path).Inc()

	setCorsHeaders(w)

	if r.Method == "OPTIONS" {
		return
	}

	target, err := parseTargetURL(r.URL.Query())
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid target URL: %v", err), http.StatusBadRequest)
		return
	}

	if !isDomainAllowed(target) {
		http.Error(w, "Domain not allowed", http.StatusForbidden)
		return
	}
	targetURL := target.String()

	useCache := isCacheableRequest(r)
	if useCache {
		cacheMutex.RLock()
		if entry, ok := cache.Get(targetURL); ok {
			cacheMutex.RUnlock()
			cacheHitCounter.Inc()
			cachedEntry, ok := entry.(cacheEntry)
			if !ok {
				log.Printf("Cache entry type assertion failed for %s", targetURL)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if matchHeader(r, "If-None-Match", cachedEntry.etag) || matchHeader(r, "If-Modified-Since", cachedEntry.lastModified) {
				copyResponseHeaders(w.Header(), cachedEntry.headers)
				w.WriteHeader(http.StatusNotModified)
				return
			}

			copyResponseHeaders(w.Header(), cachedEntry.headers)
			w.WriteHeader(cachedEntry.statusCode)
			w.Write(cachedEntry.content)
			return
		}
		cacheMutex.RUnlock()
		cacheMissCounter.Inc()
	}

	forwardRequest(w, r, target, useCache)
}

const (
	corsAllowMethods  = "GET, HEAD, POST, OPTIONS"
	corsAllowHeaders  = "Content-Type, Range, If-Range, If-None-Match, If-Modified-Since"
	corsExposeHeaders = "Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified, Content-Type"
)

// setCorsHeaders installs the proxy's CORS policy. It is applied to every
// response, including preflights, which are answered without contacting the
// origin.
func setCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
	w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
	w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
}

// parseTargetURL extracts the target from the "url" query parameter. Errors
// never quote the raw value, which may carry signed-URL secrets.
func parseTargetURL(query url.Values) (*url.URL, error) {
	raw := query.Get("url")
	if raw == "" {
		return nil, errors.New("query parameter 'url' is missing")
	}

	target, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("target is not a parseable URL")
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	return target, nil
}

// validateTarget accepts only absolute HTTP(S) URLs with a host and without
// embedded credentials.
func validateTarget(target *url.URL) error {
	if target.Scheme != "http" && target.Scheme != "https" {
		return errors.New("target must be an absolute http or https URL")
	}
	if target.Hostname() == "" {
		return errors.New("target URL has no host")
	}
	if target.User != nil {
		return errors.New("target URL must not contain credentials")
	}
	return nil
}

func isDomainAllowed(target *url.URL) bool {
	if allowAllDomains {
		return true
	}
	return allowedDomains[strings.ToLower(target.Hostname())]
}

// redactURL renders a URL for logs and error messages without its query
// string, fragment or credentials.
func redactURL(u *url.URL) string {
	redacted := *u
	redacted.User = nil
	redacted.Fragment = ""
	redacted.RawFragment = ""
	if redacted.RawQuery != "" {
		redacted.RawQuery = "REDACTED"
	}
	return redacted.String()
}

// upstreamErrorReason describes a client.Do failure without the request URL
// that *url.Error would otherwise embed.
func upstreamErrorReason(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func forwardRequest(w http.ResponseWriter, r *http.Request, target *url.URL, useCache bool) {
	targetURL := target.String()
	var body io.Reader
	if r.ContentLength != 0 {
		body = r.Body
	}
	// Bound the upstream fetch to the client's request: a departing client
	// cancels it.
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, body)
	if err != nil {
		log.Printf("Error creating request for %s: %v", redactURL(target), err)
		http.Error(w, "Error creating upstream request", http.StatusInternalServerError)
		return
	}
	req.ContentLength = r.ContentLength
	req.Header = upstreamRequestHeaders(r.Header)

	if useCache {
		cacheMutex.RLock()
		if entry, ok := cache.Get(targetURL); ok {
			cachedEntry, ok := entry.(cacheEntry)
			if !ok {
				cacheMutex.RUnlock()
				log.Printf("Cache entry type assertion failed for %s", targetURL)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if cachedEntry.etag != "" {
				req.Header.Set("If-None-Match", cachedEntry.etag)
			}
			if cachedEntry.lastModified != "" {
				req.Header.Set("If-Modified-Since", cachedEntry.lastModified)
			}
		}
		cacheMutex.RUnlock()
	}

	resp, err := client.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			// The client left; there is nobody to answer and nothing failed.
			log.Printf("Client disconnected before %s responded", redactURL(target))
			return
		}
		reason := upstreamErrorReason(err)
		log.Printf("Upstream request for %s failed: %v", redactURL(target), reason)
		if errors.Is(reason, errRedirectNotAllowed) {
			http.Error(w, "Redirect target not allowed", http.StatusForbidden)
			return
		}
		http.Error(w, fmt.Sprintf("Upstream request failed: %v", reason), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	responseHeaders := upstreamResponseHeaders(resp)
	copyResponseHeaders(w.Header(), responseHeaders)
	w.WriteHeader(resp.StatusCode)

	var captured *bytes.Buffer
	if useCache && isCacheableResponse(resp) && !isStreamingResponse(resp) {
		captured = new(bytes.Buffer)
	} else {
		log.Printf("Streaming response for %s", redactURL(target))
	}

	if err := streamBody(w, resp.Body, captured); err != nil {
		var writeErr *clientWriteError
		if r.Context().Err() != nil || errors.As(err, &writeErr) {
			log.Printf("Client disconnected while streaming %s", redactURL(target))
			return
		}
		// Headers are already sent, so an error status is impossible. Abort
		// the connection so the client sees a truncated response instead of
		// a clean end or an error message appended to the body.
		log.Printf("Error streaming response for %s: %v", redactURL(target), err)
		panic(http.ErrAbortHandler)
	}

	if captured != nil {
		cacheMutex.Lock()
		cache.Add(targetURL, cacheEntry{
			content:      captured.Bytes(),
			headers:      responseHeaders,
			statusCode:   resp.StatusCode,
			etag:         resp.Header.Get("ETag"),
			lastModified: resp.Header.Get("Last-Modified"),
		})
		cacheMutex.Unlock()
	}
}

// streamBuffer is the copy buffer size for proxied bodies.
const streamBuffer = 32 * 1024

// clientWriteError marks a failure writing to the downstream client, as
// opposed to reading from the upstream.
type clientWriteError struct{ err error }

func (e *clientWriteError) Error() string { return "write to client: " + e.err.Error() }
func (e *clientWriteError) Unwrap() error { return e.err }

// streamBody copies src to w through a bounded buffer, flushing after every
// chunk so live and progressively loaded media reach the client promptly.
// When capture is non-nil the bytes are also accumulated there.
func streamBody(w http.ResponseWriter, src io.Reader, capture *bytes.Buffer) error {
	controller := http.NewResponseController(w)
	buf := make([]byte, streamBuffer)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return &clientWriteError{err}
			}
			if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return &clientWriteError{err}
			}
			if capture != nil {
				capture.Write(buf[:n])
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func isCacheableRequest(r *http.Request) bool {
	if r.Method != "GET" {
		return false
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Range") != "" {
		return false
	}
	return true
}

func isCacheableResponse(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Vary") != "" {
		return false
	}
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	for _, directive := range strings.Split(cacheControl, ",") {
		switch strings.TrimSpace(directive) {
		case "private", "no-store", "no-cache":
			return false
		}
	}
	return true
}

func isStreamingResponse(resp *http.Response) bool {
	if resp.ContentLength < 0 {
		return true
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "video/") ||
		strings.HasPrefix(resp.Header.Get("Content-Type"), "audio/") {
		return true
	}
	return false
}

// hopByHopHeaders are connection-scoped (RFC 9110 section 7.6.1) and are
// never forwarded in either direction.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders deletes the standard hop-by-hop headers and every
// header named by a Connection header.
func removeHopByHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// upstreamRequestHeaders derives the headers sent to the origin from the
// client's request headers.
func upstreamRequestHeaders(clientHeaders http.Header) http.Header {
	h := clientHeaders.Clone()
	if h == nil {
		h = make(http.Header)
	}
	removeHopByHopHeaders(h)
	// The outgoing request's own body and target determine these.
	h.Del("Host")
	h.Del("Content-Length")
	// Compressed bytes do not share the coordinates of the byte range the
	// client asked for.
	if h.Get("Range") != "" || h.Get("If-Range") != "" {
		h.Set("Accept-Encoding", "identity")
	}
	return h
}

// upstreamResponseHeaders returns the end-to-end headers of an origin
// response that may be relayed to the client. Content-Length survives only
// when the body bytes are relayed unchanged.
func upstreamResponseHeaders(resp *http.Response) http.Header {
	h := resp.Header.Clone()
	if h == nil {
		h = make(http.Header)
	}
	removeHopByHopHeaders(h)
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			delete(h, name)
		}
	}
	if resp.Uncompressed {
		h.Del("Content-Length")
	}
	return h
}

// copyResponseHeaders copies relayable headers into dst. Upstream CORS
// headers never override the proxy's own policy.
func copyResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			continue
		}
		dst[name] = append([]string(nil), values...)
	}
}

func matchHeader(r *http.Request, headerName, headerValue string) bool {
	h := r.Header.Get(headerName)
	if h == "" {
		return false
	}
	return h == headerValue
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
func getEnvAsInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		intValue, err := strconv.Atoi(value)
		if err == nil {
			return intValue
		}
	}
	return fallback
}
