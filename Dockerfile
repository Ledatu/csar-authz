# syntax=docker/dockerfile:1
# Production Dockerfile. Build context: csar-authz/ directory.
# Strips replace directives so go.mod resolves from the module proxy.
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN sed -i '/^replace /d' go.mod && go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /csar-authz ./cmd/csar-authz

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
RUN adduser -D -u 10001 csar
COPY --from=builder /csar-authz /usr/local/bin/csar-authz
USER csar
ENTRYPOINT ["csar-authz"]
