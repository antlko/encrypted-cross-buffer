# encrypted-cross-buffer
GO      ?= go
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race vet fmt e2e docker-build

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ecb ./cmd/ecb
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ecb-relay ./cmd/ecb-relay

test:
	$(GO) test ./... -count=1

race:
	$(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

# fmt fails (non-zero) when files need formatting; run `gofmt -w .` to fix.
fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# End-to-end CLI test: relay + 3 devices with fake clipboards in temp dirs.
# Never touches the real clipboard, keychain or config.
e2e:
	bash test/e2e/e2e.sh

docker-build:
	docker build -t ecb-relay:local .
