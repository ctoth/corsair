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

### Environment Variables

- `CORSAIR_PORT`: Port to run the proxy server on (default: `8080`).
- `CORSAIR_INTERFACE`: Network interface to listen on (default: `localhost`). This can be overridden by setting the `CORSAIR_INTERFACE` environment variable when running the Docker container.
- `CORSAIR_DOMAINS`: Comma-separated list of allowed domains for forwarding (default: `*` for all).
- `CORSAIR_TIMEOUT`: Timeout in seconds for HTTP client (default: `15`).

## Contributing

Please feel free to contribute to this project. Pull requests are welcome.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
