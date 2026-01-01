FROM golang:1.25.3-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN rm -rf /root/.cache/go-build && \
    rm -rf /go/pkg/mod && \
    CGO_ENABLED=0 GOOS=linux go build -o server main.go

FROM golang:1.25.3-alpine

RUN apk add --no-cache ca-certificates git

WORKDIR /app

COPY --from=builder /app/server .

COPY static ./static

CMD ["./server"]
