BINARY := token-auth-proxy
IMAGE  := ghcr.io/thisisqasim/token-auth-proxy

.PHONY: build run fmt lint test test-integration test-load bench test-all tidy \
	docker-build docker-buildx release-dry-run clean

build:
	go build -trimpath -o bin/$(BINARY) ./cmd/$(BINARY)

run: build
	./bin/$(BINARY) -config config.example.yaml

fmt:
	gofmt -l -s -w .
	goimports -l -w .

lint:
	golangci-lint run --build-tags=integration,load ./...

test:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

test-integration: build
	go test -tags=integration -race -timeout=120s ./test/integration/...

test-load: build
	go test -tags=load -race -timeout=120s ./test/load/...

bench:
	go test -bench=. -benchmem -run='^$$' ./internal/proxy/...

test-all: test test-integration test-load

tidy:
	go mod tidy

docker-build:
	docker build -t $(IMAGE):dev .

docker-buildx:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE):dev .

# Builds everything a real tag push would (binaries for all platforms,
# archives, checksums, changelog, both docker images) without tagging or
# publishing anything — the way to validate .goreleaser.yaml locally.
release-dry-run:
	goreleaser release --snapshot --clean --skip=publish

clean:
	rm -rf bin coverage.out dist load-test-report.json
