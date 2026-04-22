BINARY     = mergen
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   = -ldflags "-X main.version=$(VERSION) -s -w"
GOFLAGS   = -trimpath

.PHONY: all build install clean test tidy release

all: build

## build: compile for the current platform
build:
	go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY) .

## install: install to /usr/local/bin
install: build
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed to /usr/local/bin/$(BINARY)"

## release: build universal macOS binary (arm64 + amd64)
release:
	mkdir -p dist
	GOOS=darwin GOARCH=arm64  go build $(GOFLAGS) $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64  go build $(GOFLAGS) $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64 .
	lipo -create -output dist/$(BINARY)-darwin-universal \
		dist/$(BINARY)-darwin-arm64 \
		dist/$(BINARY)-darwin-amd64
	@echo "Universal binary: dist/$(BINARY)-darwin-universal"

## test: run all tests
test:
	go test ./...

## tidy: tidy and vendor modules
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -rf $(BINARY) dist/
