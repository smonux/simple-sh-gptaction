GOCACHE := $(CURDIR)/.gocache
GOMODCACHE := $(CURDIR)/.gomodcache
GOPATH := $(CURDIR)/.gopath
GOTOOLCHAIN := local

.PHONY: build test

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go build ./cmd/server
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) GOTOOLCHAIN=$(GOTOOLCHAIN) go build ./cmd/executor

test: build
	./scripts/test.sh
