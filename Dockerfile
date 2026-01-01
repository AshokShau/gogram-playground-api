FROM golang:1.25.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOCACHE=off go build -a -installsuffix cgo -o server main.go

# Final stage
FROM golang:1.25.3-alpine

# Install runtime dependencies
RUN apk add --no-cache ca-certificates git

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/server .

# Copy static files (embedded, but keeping for reference)
COPY static ./static

# Expose port (Render will set PORT env var)
EXPOSE 10000

# Run the server
CMD ["./server"]
