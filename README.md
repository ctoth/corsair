<img src="logo.png" alt="Logo" width="200"/>

# Corsair

Corsair is a high-performance HTTP proxy server written in Go that enables cross-origin requests by handling CORS headers. It acts as an intermediary between your frontend application and APIs that don't support CORS, allowing you to make requests to any domain while maintaining security and performance.

## Features

- **CORS Handling**: Automatically adds appropriate CORS headers to enable cross-origin requests
- **Smart Caching**: Built-in LRU cache that honours `max-age`/`Expires`, revalidates stale entries with ETag and Last-Modified, and is bounded to 1 MiB per entry and 32 MiB in total. Media, playlists/manifests, range requests and credentialed requests are never cached
- **Performance Monitoring**: Prometheus metrics for request tracking and performance analysis
- **Streaming Support**: Streams bodies with per-chunk flushing, passes Range/If-Range requests and 206/416 responses through unchanged, and cancels the upstream fetch when the client disconnects
- **Flexible Configuration**: Configurable via both environment variables and command-line flags
- **Health Checks**: Built-in health check endpoint
- **Domain Filtering**: Optional whitelist of allowed domains
- **Redirect Handling**: Follows up to 10 redirects, re-checking the domain allowlist on every hop
- **Request Forwarding**: Preserves end-to-end headers and request methods; hop-by-hop headers are dropped

## Getting Started

You can run Corsair either directly as a Go binary or using Docker.

### Prerequisites

#### For Docker
- Docker

#### For Direct Installation
- Go 1.16 or higher
- Git

### Installation

#### Using Docker

1. Build the image:
```sh
docker build -t corsair .
```

2. Run the container:
```sh
docker run -d -p 8080:8080 --name corsair corsair
```

#### Using Go

1. Clone the repository:
```sh
git clone https://github.com/yourusername/corsair.git
cd corsair
```

2. Build the binary:
```sh
go build -o corsair
```

3. Run the server:
```sh
./corsair
```

## Usage

### Basic Usage

To proxy a request through Corsair, add your target URL as a query parameter:

```
http://localhost:8080/?url=https://api.example.com/data
```

### API Documentation

#### Main Proxy Endpoint (/)
- Method: GET, HEAD, POST, OPTIONS
- Query Parameters:
  - `url`: (Required) The target URL to proxy: an absolute `http` or `https` URL with a host and no embedded credentials
- Example: `curl "http://localhost:8080/?url=https://api.example.com/data"`
- CORS: `Access-Control-Allow-Origin: *`. Allowed request headers: `Content-Type, Range, If-Range, If-None-Match, If-Modified-Since`. Exposed response headers: `Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified, Content-Type`. Preflight `OPTIONS` requests are answered without contacting the target.

#### Health Check (/health)
- Method: GET
- Returns: 200 OK when service is healthy
- Example: `curl http://localhost:8080/health`

#### Metrics (/metrics)
- Method: GET
- Returns: Prometheus metrics
- Example: `curl http://localhost:8080/metrics`

### Configuration

Corsair can be configured through environment variables or command-line flags. Flags take precedence over environment variables.

#### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CORSAIR_PORT` | Server port | 8080 | `8081` |
| `CORSAIR_INTERFACE` | Network interface | localhost | `0.0.0.0` |
| `CORSAIR_DOMAINS` | Allowed domains (comma-separated) | * | `api1.com,api2.com` |
| `CORSAIR_TIMEOUT` | Seconds to wait for upstream response headers (0 = no limit). Streamed bodies have no total deadline | 0 | `30` |
| `CORSAIR_CACHE_SIZE` | Maximum cache entries | 100 | `1000` |

#### Command-Line Flags

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `--port` | Server port | 8080 | `--port 8081` |
| `--interface` | Network interface | localhost | `--interface 0.0.0.0` |
| `--domains` | Allowed domains | * | `--domains api1.com,api2.com` |
| `--timeout` | Upstream response-header timeout (seconds) | 0 | `--timeout 30` |
| `--cache-size` | Maximum cache entries | 100 | `--cache-size 1000` |
| `--version` | Show version info | false | `--version` |

### Monitoring

Corsair exposes Prometheus metrics at `/metrics` including:

- `corsair_requests_total`: Total number of processed requests
- `corsair_request_duration_seconds`: Request duration histogram
- `corsair_cache_hits_total`: Cache hit count
- `corsair_cache_misses_total`: Cache miss count

### Troubleshooting

#### Common Issues

1. **Connection Refused**
   - Check if the port is already in use
   - Verify firewall settings
   - Ensure correct interface binding

2. **Domain Not Allowed**
   - Check `CORSAIR_DOMAINS` configuration
   - Verify target URL format

3. **Timeout Errors**
   - Increase `CORSAIR_TIMEOUT` value
   - Check target API responsiveness

#### Debug Logging

Run with environment variable `DEBUG=1` for verbose logging:

```sh
DEBUG=1 ./corsair
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Go](https://golang.org/)
- Uses [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru) for caching
- Metrics powered by [Prometheus](https://prometheus.io/)
