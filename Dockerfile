# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.5 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/token-auth-proxy ./cmd/token-auth-proxy

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /out/token-auth-proxy /usr/local/bin/token-auth-proxy
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/token-auth-proxy"]
CMD ["--config", "/etc/token-auth-proxy/config.yaml"]
