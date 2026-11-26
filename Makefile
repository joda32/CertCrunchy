VERSION ?= $(shell git describe --tags --match 'v2*' --always --dirty 2>/dev/null || echo 2.0.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race live lint clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o certcrunchy ./cmd/certcrunchy

test:
	go test ./...

race:
	go test -race ./...

# Real queries against keyless sources (and keyed ones if configured).
# LIVE_DOMAIN=example.org LIVE_SOURCES=crtsh-db,certspotter make live
live:
	go test -tags live -run Live -v ./internal/source/

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

clean:
	rm -rf certcrunchy dist
