# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
FROM golang:1.18 as builder

# Copy the local package files to the container's workspace.
WORKDIR /go/src/app
COPY . .

# Fetch dependencies.
# Using go get.
RUN go get -d -v ./...

# Build the command inside the container.
# (You may fetch or manage dependencies here,
# either manually or with a tool like "godep".)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# Use a Docker multi-stage build to create a lean production image for Corsair.
# https://docs.docker.com/develop/develop-images/multistage-build/
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from the builder stage.
COPY --from=builder /go/src/app/corsair .

# Run the binary program produced by `go install`.
CMD ["./corsair"]
