# Makefile — build & rilis bughound (single binary, go:embed, CGO off).
# VERSION otomatis dari git tag; override: make release VERSION=v0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      ?= go

.PHONY: build test vet run release clean version help

help: ## tampilkan target yang tersedia
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'

build: ## build binary lokal ke bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/bughound ./cmd/bughound

test: ## jalankan seluruh test
	$(GO) test ./... -count=1

vet: ## go vet seluruh paket
	$(GO) vet ./...

run: build ## build lalu jalankan (localhost)
	./bin/bughound

release: ## cross-compile semua target rilis + paket ke dist/
	VERSION=$(VERSION) bash scripts/build-release.sh

clean: ## hapus artefak build
	rm -rf bin dist

version: ## cetak versi yang akan di-embed
	@echo $(VERSION)
