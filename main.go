package main

import (
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

	"github.com/caddyserver/certmagic"
	lru "github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	port             int
	listenAddr       string
	allowedDomains   map[string]bool
	allowAllDomains  bool
	clientTimeout    time.Duration
	useTLS           bool
	certDomains      string
	letsEncryptEmail string // New variable for Let's Encrypt account email
	cacheSize        int
	client          *http.Client
	cache            *lru.Cache
	cacheMutex       sync.RWMutex
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
	etag         string
	lastModified string
}

func init() {
	var domains string
	var timeout int
	flag.IntVar(&port, "port", getEnvAsInt("CORSAIR_PORT", 8080), "Port to run the proxy server on")
	flag.StringVar(&listenAddr, "interface", getEnv("CORSAIR_INTERFACE", "localhost"), "Network interface to listen on")
	flag.StringVar(&domains, "domains", getEnv("CORSAIR_DOMAINS", "*"), "Comma-separated list of allowed domains for forwarding, default to '*' for all")
	flag.IntVar(&timeout, "timeout", getEnvAsInt("CORSAIR_TIMEOUT", 15), "Timeout in seconds for HTTP client")

	flag.BoolVar(&useTLS, "use-https", getEnvAsBool("CORSAIR_USE_HTTPS", false), "Enable HTTPS using CertMagic")
	flag.StringVar(&certDomains, "cert-domains", getEnv("CORSAIR_CERT_DOMAINS", ""), "Comma-separated list of domains for the TLS certificate")
	flag.StringVar(&letsEncryptEmail, "letsencrypt-email", getEnv("CORSAIR_LETSENCRYPT_EMAIL", ""), "Email address to use for Let's Encrypt account")

	var cacheSizeEnv int
	flag.IntVar(&cacheSize, "cache-size", getEnvAsInt("CORSAIR_CACHE_SIZE", 100), "Size of the cache")
	cacheSizeEnv = getEnvAsInt("CORSAIR_CACHE_SIZE", cacheSize)
	flag.Parse()
	cacheSize = cacheSizeEnv

	allowedDomains = make(map[string]bool)
	if domains == "*" {
		allowAllDomains = true
	} else {
		for _, domain := range strings.Split(domains, ",") {
			allowedDomains[domain] = true
		}
	}

	var err error
	cache, err = lru.New(cacheSize)
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	clientTimeout = time.Duration(timeout) * time.Second
	client = &http.Client{
		Timeout: clientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // This will allow the client to follow redirects.
		},
	}

	prometheus.MustRegister(requestCounter, requestDuration, cacheHitCounter, cacheMissCounter)
}

func main() {
	http.HandleFunc("/", proxyHandler)
	http.HandleFunc("/health", healthCheckHandler)
	http.Handle("/metrics", promhttp.Handler())
	address := fmt.Sprintf("%s:%d", listenAddr, port)
	log.Printf("Proxy server started on %s\n", address)

	if useTLS {
		certmagic.DefaultACME.Email = letsEncryptEmail // Set the Let's Encrypt account email
		if certDomains == "" {
			log.Fatal("No domains specified for HTTPS certificate")
		}
		domains := strings.Split(certDomains, ",")
		certmagic.HTTPS(domains, nil)
	} else {
		log.Fatal(http.ListenAndServe(address, nil))
	}
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	timer := prometheus.NewTimer(requestDuration.WithLabelValues(r.URL.Path))
	defer timer.ObserveDuration()

	requestCounter.WithLabelValues(r.Method, r.URL.Path).Inc()

	setCorsHeaders(w)

	if r.Method == "OPTIONS" {
		return
	}

	targetURL, err := parseTargetURL(r.URL.Query())
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid target URL: %v", err), http.StatusBadRequest)
		return
	}

	if !isDomainAllowed(targetURL) {
		http.Error(w, "Domain not allowed", http.StatusForbidden)
		return
	}

	if r.Method == "GET" {
		cacheMutex.RLock()
		if entry, ok := cache.Get(targetURL); ok {
			cacheMutex.RUnlock()
			cachedEntry, ok := entry.(cacheEntry)
			if !ok {
				log.Printf("Cache entry type assertion failed for %s", targetURL)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if matchHeader(r, "If-None-Match", cachedEntry.etag) || matchHeader(r, "If-Modified-Since", cachedEntry.lastModified) {
				w.WriteHeader(http.StatusNotModified)
				return
			}

			w.Write(cachedEntry.content)
			return
		}
		cacheMutex.RUnlock()
	}

	forwardRequest(w, r, targetURL)
}

func setCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func parseTargetURL(query url.Values) (string, error) {
	targetURL := query.Get("url")
	if targetURL == "" {
		return "", fmt.Errorf("query parameter 'url' is missing")
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}

	return parsedURL.String(), nil
}

func isDomainAllowed(targetURL string) bool {
	if allowAllDomains {
		return true
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("Error parsing URL: %v", err)
		return false
	}

	_, ok := allowedDomains[parsedURL.Hostname()]
	return ok
}

func forwardRequest(w http.ResponseWriter, r *http.Request, targetURL string) {
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating new request: %v", err), http.StatusInternalServerError)
		return
	}

	copyHeaders(req.Header, r.Header)

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

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error forwarding request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if r.Method == "GET" && !isStreamingResponse(resp) {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		cacheMutex.Lock()
		cache.Add(targetURL, cacheEntry{
			content:      bodyBytes,
			etag:         resp.Header.Get("ETag"),
			lastModified: resp.Header.Get("Last-Modified"),
		})
		cacheMutex.Unlock()

		w.Write(bodyBytes)
	} else {
		io.Copy(w, resp.Body)
	}
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

func copyHeaders(dst, src http.Header) {
	protectedHeaders := []string{"Host", "Content-Length", "Connection"}
	isProtectedHeader := func(header string) bool {
		for _, protectedHeader := range protectedHeaders {
			if strings.EqualFold(protectedHeader, header) {
				return true
			}
		}
		return false
	}

	for k, vv := range src {
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
	return r.Header.Get(headerName) == headerValue
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

func getEnvAsBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		boolValue, err := strconv.ParseBool(value)
		if err == nil {
			return boolValue
		}
	}
	return fallback
}
