GOCACHE := $(CURDIR)/.gocache
GOMODCACHE := $(CURDIR)/.gomodcache
GOPATH := $(CURDIR)/.gopath
GOTOOLCHAIN ?= auto

.PHONY: build test test-mcp audit prepare-publication install-service uninstall-service install-user-service uninstall-user-service

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go build -trimpath ./cmd/server
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go build -trimpath ./cmd/executor

test: build
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go test ./...
	./scripts/test.sh

test-mcp: build
	uv run scripts/test-mcp.py

audit:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go vet ./...
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

prepare-publication:
	uv run scripts/prepare-publication.py

install-service: build
	sudo ./scripts/install-systemd.sh

uninstall-service:
	sudo ./scripts/install-systemd.sh --uninstall

install-user-service: build
	./scripts/install-user-systemd.sh

uninstall-user-service:
	./scripts/install-user-systemd.sh --uninstall
