# Build stage
FROM golang:1.26.5-alpine AS builder

WORKDIR /src

# Copy module files first for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the repository.
COPY . .

# Build the relay binary.
RUN CGO_ENABLED=0 go build -o /bin/httpsse-relay ./examples/httpsse-relay

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/httpsse-relay /httpsse-relay

EXPOSE 8080

ENTRYPOINT ["/httpsse-relay"]
