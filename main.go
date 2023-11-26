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

	lru "github.com/hashicorp/golang-lru"
)

var (
	port            int
	listenAddr      string
	allowedDomains  map[string]bool
	allowAllDomains bool
	clientTimeout   time.Duration
	client          *http.Client
	cache           *lru.Cache
	cacheMutex      sync.Mutex
)

type cacheEntry struct {
	content      []byte
	etag         string
	lastModified string
}

func init() {
	var domains string
	var timeout int
	flag.IntVar(&port, "port", getEnvAsInt("PORT", 8080), "Port to run the proxy server on")
	flag.StringVar(&listenAddr, "interface", getEnv("INTERFACE", "0.0.0.0"), "Network interface to listen on")
	flag.StringVar(&domains, "domains", getEnv("DOMAINS", "*"), "Comma-separated list of allowed domains for forwarding, default to '*' for all")
	flag.IntVar(&timeout, "timeout", getEnvAsInt("TIMEOUT", 15), "Timeout in seconds for HTTP client")
	flag.Parse()

	allowedDomains = make(map[string]bool)
	if domains == "*" {
		allowAllDomains = true
	} else {
		for _, domain := range strings.Split(domains, ",") {
			allowedDomains[domain] = true
		}
	}

	var err error
	cache, err = lru.New(100) // Cache size of 100
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	clientTimeout = time.Duration(timeout) * time.Second
	client = &http.Client{
		Timeout: clientTimeout,
	}
}

func main() {
	http.HandleFunc("/", proxyHandler)
	address := fmt.Sprintf("%s:%d", listenAddr, port)
	log.Printf("Proxy server started on %s with a timeout of %v\n", address, clientTimeout)
	log.Fatal(http.ListenAndServe(address, nil))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w)

	if r.Method == "OPTIONS" {
		return
	}

	targetURL, err := parseTargetURL(r.URL.Path)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid target URL: %v", err), http.StatusBadRequest)
		return
	}

	if !isDomainAllowed(targetURL) {
		http.Error(w, "Domain not allowed", http.StatusForbidden)
		return
	}

	if r.Method == "GET" {
		cacheMutex.Lock()
		if entry, ok := cache.Get(targetURL); ok {
			cachedEntry, ok := entry.(cacheEntry)
			cacheMutex.Unlock()
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
		cacheMutex.Unlock()
	}

	log.Printf("Forwarding request to %s\n", targetURL)
	forwardRequest(w, r, targetURL)
}

func setCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func parseTargetURL(path string) (string, error) {
	path = strings.TrimPrefix(path, "/")

	if _, err := url.ParseRequestURI(path); err != nil {
		return "", err
	}

	return path, nil
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

	cacheMutex.Lock()
	if entry, ok := cache.Get(targetURL); ok {
		cachedEntry, ok := entry.(cacheEntry)
		if !ok {
			cacheMutex.Unlock()
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
	cacheMutex.Unlock()

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
	for k, vv := range src {
		dst[k] = vv
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
