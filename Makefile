# Makefile, build & release bughound (single binary, go:embed, CGO off).
# VERSION comes from the git tag automatically; override: make release VERSION=v0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      ?= go

.PHONY: build test vet run release clean version help

help: ## show the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'

build: ## build the local binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/bughound ./cmd/bughound

test: ## run the whole test suite
	$(GO) test ./... -count=1

vet: ## go vet every package
	$(GO) vet ./...

run: build ## build then run (localhost)
	./bin/bughound

release: ## cross-compile all release targets + package into dist/
	VERSION=$(VERSION) bash scripts/build-release.sh

clean: ## remove build artifacts
	rm -rf bin dist

version: ## print the version that gets embedded
	@echo $(VERSION)
