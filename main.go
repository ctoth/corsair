package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
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
	cache           *responseCache
	// nowFunc is the cache's clock; tests replace it.
	nowFunc = time.Now
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
	// expires is when the entry stops being fresh and must be revalidated.
	expires time.Time
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
	cache, err = newResponseCache(cacheSize, maxCacheBytes, maxCacheEntryBytes)
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
	useCache := isCacheableRequest(r)
	var stale *cacheEntry
	if useCache {
		if entry, ok := cache.get(target.String()); ok {
			if nowFunc().Before(entry.expires) {
				cacheHitCounter.Inc()
				serveCachedEntry(w, r, entry)
				return
			}
			stale = entry
		}
		cacheMissCounter.Inc()
	}

	forwardRequest(w, r, target, useCache, stale)
}

// serveCachedEntry answers from a fresh or just-revalidated entry, honouring
// the client's own validators.
func serveCachedEntry(w http.ResponseWriter, r *http.Request, entry *cacheEntry) {
	copyResponseHeaders(w.Header(), entry.headers)
	if clientHasCurrentCopy(r, entry) {
		w.Header().Del("Content-Length")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(entry.statusCode)
	w.Write(entry.content)
}

// clientHasCurrentCopy evaluates If-None-Match (weak comparison) or, when
// that is absent, If-Modified-Since against a cached entry.
func clientHasCurrentCopy(r *http.Request, entry *cacheEntry) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if entry.etag == "" {
			return false
		}
		for _, tag := range strings.Split(inm, ",") {
			tag = strings.TrimSpace(tag)
			if tag == "*" || strings.TrimPrefix(tag, "W/") == strings.TrimPrefix(entry.etag, "W/") {
				return true
			}
		}
		return false
	}
	ims, err := http.ParseTime(r.Header.Get("If-Modified-Since"))
	if err != nil {
		return false
	}
	lastModified, err := http.ParseTime(entry.lastModified)
	if err != nil {
		return false
	}
	return !lastModified.After(ims)
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

// forwardRequest relays the request to the origin. When stale is non-nil it
// is an expired cache entry for this target, revalidated with its validators.
func forwardRequest(w http.ResponseWriter, r *http.Request, target *url.URL, useCache bool, stale *cacheEntry) {
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

	if stale != nil {
		if stale.etag == "" && stale.lastModified == "" {
			// Nothing to revalidate with: drop it and fetch afresh.
			cache.remove(targetURL)
			stale = nil
		} else {
			// Revalidate with the stored validators, not the client's; the
			// client's own validators are applied to the refreshed entry.
			req.Header.Del("If-None-Match")
			req.Header.Del("If-Modified-Since")
			if stale.etag != "" {
				req.Header.Set("If-None-Match", stale.etag)
			}
			if stale.lastModified != "" {
				req.Header.Set("If-Modified-Since", stale.lastModified)
			}
		}
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

	if stale != nil {
		if resp.StatusCode == http.StatusNotModified {
			refreshed := stale.refreshed(responseHeaders, nowFunc())
			if nowFunc().Before(refreshed.expires) {
				cache.add(targetURL, refreshed)
			} else {
				cache.remove(targetURL)
			}
			serveCachedEntry(w, r, refreshed)
			return
		}
		cache.remove(targetURL)
	}

	if useCache {
		if lifetime := cacheLifetime(resp, target, nowFunc()); lifetime > 0 {
			// cacheLifetime admits only known lengths within the entry cap,
			// so buffering is bounded. The entry is stored before the client
			// sees the last byte, so an immediate repeat request hits it.
			content := make([]byte, resp.ContentLength)
			if _, err := io.ReadFull(resp.Body, content); err != nil {
				if r.Context().Err() != nil {
					log.Printf("Client disconnected before %s responded", redactURL(target))
					return
				}
				log.Printf("Error reading response for %s: %v", redactURL(target), err)
				http.Error(w, "Upstream response was truncated", http.StatusBadGateway)
				return
			}
			entry := &cacheEntry{
				content:      content,
				headers:      responseHeaders,
				statusCode:   resp.StatusCode,
				etag:         resp.Header.Get("ETag"),
				lastModified: resp.Header.Get("Last-Modified"),
				expires:      nowFunc().Add(lifetime),
			}
			cache.add(targetURL, entry)
			copyResponseHeaders(w.Header(), responseHeaders)
			w.WriteHeader(resp.StatusCode)
			w.Write(content)
			return
		}
	}

	copyResponseHeaders(w.Header(), responseHeaders)
	w.WriteHeader(resp.StatusCode)
	log.Printf("Streaming response for %s", redactURL(target))

	if err := streamBody(w, resp.Body); err != nil {
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
func streamBody(w http.ResponseWriter, src io.Reader) error {
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
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// isCacheableRequest reports whether a request may be answered from, or
// populate, the shared cache. Credentialed and partial requests never are:
// a cached whole object must never answer a range request.
func isCacheableRequest(r *http.Request) bool {
	if r.Method != "GET" {
		return false
	}
	for _, name := range []string{"Authorization", "Cookie", "Range", "If-Range"} {
		if r.Header.Get(name) != "" {
			return false
		}
	}
	return true
}

// cacheLifetime returns how long an origin response may be served from the
// cache, or zero when it must not be stored at all.
func cacheLifetime(resp *http.Response, target *url.URL, now time.Time) time.Duration {
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Vary") != "" {
		return 0
	}
	directives := cacheControlDirectives(resp.Header)
	for _, name := range []string{"private", "no-store", "no-cache"} {
		if _, ok := directives[name]; ok {
			return 0
		}
	}
	// Media is streamed and seeked by range; manifests change underneath
	// their URL. Neither belongs in the cache.
	if isMediaOrManifest(resp.Header.Get("Content-Type"), target) {
		return 0
	}
	// Unknown or oversized bodies are streamed without buffering.
	if resp.ContentLength < 0 || resp.ContentLength > maxCacheEntryBytes {
		return 0
	}
	return freshnessLifetime(resp.Header, now)
}

// manifestTypes are playlist and manifest MIME types.
var manifestTypes = map[string]bool{
	"application/vnd.apple.mpegurl": true,
	"application/x-mpegurl":         true,
	"audio/mpegurl":                 true,
	"audio/x-mpegurl":               true,
	"application/dash+xml":          true,
	"application/vnd.ms-sstr+xml":   true,
}

// manifestExtensions identify playlists served with a generic MIME type.
var manifestExtensions = []string{".m3u8", ".m3u", ".mpd"}

func isMediaOrManifest(contentType string, target *url.URL) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(contentType))
	}
	if strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") || manifestTypes[mediaType] {
		return true
	}
	p := strings.ToLower(target.Path)
	for _, ext := range manifestExtensions {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// cacheControlDirectives parses Cache-Control into lower-case directive
// names mapped to their (unquoted) arguments.
func cacheControlDirectives(h http.Header) map[string]string {
	directives := make(map[string]string)
	for _, value := range h.Values("Cache-Control") {
		for _, part := range strings.Split(value, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				directives[name] = strings.Trim(strings.TrimSpace(arg), `"`)
			}
		}
	}
	return directives
}

// freshnessLifetime computes a response's remaining freshness from
// s-maxage, max-age or Expires (relative to Date), less its Age. Responses
// without explicit freshness get zero: the proxy never guesses.
func freshnessLifetime(h http.Header, now time.Time) time.Duration {
	directives := cacheControlDirectives(h)
	var lifetime time.Duration
	if seconds, ok := directiveSeconds(directives, "s-maxage"); ok {
		lifetime = seconds
	} else if seconds, ok := directiveSeconds(directives, "max-age"); ok {
		lifetime = seconds
	} else if expires := h.Get("Expires"); expires != "" {
		expiresAt, err := http.ParseTime(expires)
		if err != nil {
			return 0 // invalid Expires means already expired
		}
		date, err := http.ParseTime(h.Get("Date"))
		if err != nil {
			date = now
		}
		lifetime = expiresAt.Sub(date)
	} else {
		return 0
	}
	if age, err := strconv.Atoi(strings.TrimSpace(h.Get("Age"))); err == nil && age > 0 {
		lifetime -= time.Duration(age) * time.Second
	}
	if lifetime < 0 {
		return 0
	}
	return lifetime
}

func directiveSeconds(directives map[string]string, name string) (time.Duration, bool) {
	arg, ok := directives[name]
	if !ok {
		return 0, false
	}
	seconds, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || seconds < 0 {
		return 0, true
	}
	return time.Duration(seconds) * time.Second, true
}

// refreshed merges the headers of a 304 revalidation into a copy of the
// entry (RFC 9111 section 4.3.4) and recomputes its freshness. The stored
// body and its length are kept.
func (e *cacheEntry) refreshed(notModified http.Header, now time.Time) *cacheEntry {
	headers := e.headers.Clone()
	for name, values := range notModified {
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		headers[name] = append([]string(nil), values...)
	}
	updated := *e
	updated.headers = headers
	if etag := headers.Get("ETag"); etag != "" {
		updated.etag = etag
	}
	if lastModified := headers.Get("Last-Modified"); lastModified != "" {
		updated.lastModified = lastModified
	}
	updated.expires = now.Add(freshnessLifetime(headers, now))
	return &updated
}

// Cache limits. The entry count is configurable with -cache-size.
const (
	maxCacheEntryBytes = 1 << 20  // largest body stored
	maxCacheBytes      = 32 << 20 // total body bytes stored
)

// responseCache is an LRU of whole 200 responses bounded by entry count,
// total body bytes and per-entry body bytes. It is safe for concurrent use.
type responseCache struct {
	mu            sync.Mutex
	entries       *lru.Cache
	bytes         int64
	maxEntries    int
	maxBytes      int64
	maxEntryBytes int64
}

func newResponseCache(maxEntries int, maxBytes, maxEntryBytes int64) (*responseCache, error) {
	c := &responseCache{maxEntries: maxEntries, maxBytes: maxBytes, maxEntryBytes: maxEntryBytes}
	entries, err := lru.NewWithEvict(maxEntries, func(_, value interface{}) {
		// Called synchronously from Add/Remove/RemoveOldest, with c.mu held.
		c.bytes -= int64(len(value.(*cacheEntry).content))
	})
	if err != nil {
		return nil, err
	}
	c.entries = entries
	return c, nil
}

func (c *responseCache) get(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.entries.Get(key)
	if !ok {
		return nil, false
	}
	return value.(*cacheEntry), true
}

// add stores an entry, evicting least-recently-used entries until the byte
// budget holds. It refuses entries above the per-entry cap.
func (c *responseCache) add(key string, entry *cacheEntry) bool {
	size := int64(len(entry.content))
	if size > c.maxEntryBytes || size > c.maxBytes {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.Remove(key) // re-account a replaced entry
	for c.bytes+size > c.maxBytes {
		if _, _, ok := c.entries.RemoveOldest(); !ok {
			break
		}
	}
	c.entries.Add(key, entry)
	c.bytes += size
	return true
}

func (c *responseCache) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.Remove(key)
}

func (c *responseCache) stats() (entries int, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries.Len(), c.bytes
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
