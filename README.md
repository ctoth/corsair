<img src="logo.png" alt="Logo" width="200"/>

# Corsair

This project is a simple HTTP proxy server written in Go that removes CORS (Cross-Origin Resource Sharing) restrictions by setting appropriate headers on the response.

## Features

- Removes CORS restrictions for client-side cross-origin requests.
- Caches responses to improve performance.
- Configurable through environment variables.

## Getting Started

These instructions will cover usage information for the Docker container.

### Prerequisites

- Docker

### Building the Docker Image

To build the Docker image, run the following command from the root of the repository:

```sh
docker build -t corsair .
```

### Running the Docker Container

To run the proxy server in a Docker container, execute:

```sh
docker run -d -p 8080:8080 --name my-proxy corsair
```

This will start the proxy server on port 8080.

### Configuration

The proxy server can be configured using both environment variables and command-line flags. When both are provided, command-line flags take precedence over environment variables.

#### Environment Variables

- `CORSAIR_PORT`: Port to run the proxy server on. Defaults to `8080` if not set.
- `CORSAIR_INTERFACE`: Network interface to listen on. Defaults to `localhost` if not set.
- `CORSAIR_DOMAINS`: Comma-separated list of allowed domains for forwarding. Defaults to `*` (all domains) if not set.
- `CORSAIR_TIMEOUT`: Timeout in seconds for the HTTP client. Defaults to `15` if not set.
- `CORSAIR_USE_HTTPS`: Set to `true` to enable HTTPS support using CertMagic. Defaults to `false` if not set.
- `CORSAIR_CERT_DOMAINS`: Comma-separated list of domains for the TLS certificate. Required if `CORSAIR_USE_HTTPS` is `true`.
- `CORSAIR_CACHE_SIZE`: Size of the cache. Defaults to `100` if not set.

#### Command-Line Flags

- `--port`: Specify the port to run the proxy server on.
- `--interface`: Specify the network interface to listen on.
- `--domains`: Specify the allowed domains for forwarding.
- `--timeout`: Specify the timeout in seconds for the HTTP client.
- `--use-https`: Enable HTTPS support using CertMagic.
- `--cert-domains`: Specify the domains for the TLS certificate.

For example, to start the server on port `8081` with a timeout of `10` seconds, you can use the following command with environment variables:

```sh
docker run -d -p 8081:8081 --name my-proxy -e CORSAIR_PORT=8081 -e CORSAIR_TIMEOUT=10 corsair
```

Or, you can set the environment variables and run the container without flags:

```sh
export CORSAIR_PORT=8081
export CORSAIR_TIMEOUT=10
docker run -d -p 8081:8081 --name my-proxy corsair
```

## Contributing

Please feel free to contribute to this project. Pull requests are welcome.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
