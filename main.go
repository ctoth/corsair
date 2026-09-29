package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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
	flag.IntVar(&timeout, "timeout", getEnvAsInt("CORSAIR_TIMEOUT", 0), "Timeout in seconds for HTTP client")
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
	client = &http.Client{
		Timeout:       clientTimeout,
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
				copyHeaders(w.Header(), cachedEntry.headers)
				w.WriteHeader(http.StatusNotModified)
				return
			}

			copyHeaders(w.Header(), cachedEntry.headers)
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
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("Error creating request for %s: %v", redactURL(target), err)
		http.Error(w, "Error creating upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(req.Header, r.Header)

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

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if useCache && isCacheableResponse(resp) && !isStreamingResponse(resp) {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		cacheMutex.Lock()
		cache.Add(targetURL, cacheEntry{
			content:      bodyBytes,
			headers:      cloneHeaders(resp.Header),
			statusCode:   resp.StatusCode,
			etag:         resp.Header.Get("ETag"),
			lastModified: resp.Header.Get("Last-Modified"),
		})
		cacheMutex.Unlock()

		w.Write(bodyBytes)
	} else {
		log.Printf("Streaming response for %s", redactURL(target))
		_, copyErr := io.Copy(w, resp.Body)
		if copyErr != nil {
			log.Printf("Error streaming response for %s: %v", redactURL(target), copyErr)
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
	if _, ok := resp.Header["Content-Length"]; !ok {
		return true
	}
	if resp.Header.Get("Transfer-Encoding") == "chunked" {
		return true
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "video/") ||
		strings.HasPrefix(resp.Header.Get("Content-Type"), "audio/") {
		return true
	}
	return false
}

func cloneHeaders(headers http.Header) http.Header {
	cloned := make(http.Header, len(headers))
	for key, values := range headers {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func copyHeaders(dst, src http.Header) {
	protectedHeaders := []string{"Host", "Content-Length", "Connection"}
	// Upstream CORS headers (Access-Control-*) never override the proxy's policy.

	isProtectedHeader := func(header string) bool {
		for _, h := range protectedHeaders {
			if strings.EqualFold(h, header) {
				return true
			}
		}
		return false
	}

	isCorsHeader := func(header string) bool {
		return strings.HasPrefix(http.CanonicalHeaderKey(header), "Access-Control-")
	}

	for k, vv := range src {
		if isCorsHeader(k) {
			continue // Skip copying upstream CORS headers.
		}
		if !isProtectedHeader(k) {
			dst[k] = vv
		} else {
			if _, exists := dst[k]; !exists {
				dst[k] = vv
			}
		}
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
