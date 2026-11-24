# The FIPS 140-3 Go Cryptographic Module the tests run under, as releases are built.
GOFIPS140 ?= v1.26.0
GO_TEST_ENV := GOFIPS140=$(GOFIPS140)

MODULE := github.com/nnicora/cipheron

# Tool versions, pinned (never @latest). buf's is what the CI workflow installs (and checks by content hash); the
# generators' are the ones proto/ was generated with; golangci-lint is built from source by `go install`, so it is
# built with this module's Go (a release binary built with an older Go refuses a module targeting a newer one).
BUF_VERSION ?= v1.73.0
GOLANGCI_LINT_VERSION ?= v2.13.2
PROTOC_GEN_GO_VERSION := v1.36.11
PROTOC_GEN_GO_GRPC_VERSION := v1.6.1
GRPC_GATEWAY_VERSION := v2.27.7
GOIMPORTS_VERSION := v0.36.0
PROTO_PATH := PATH="$$(go env GOPATH)/bin:$$PATH"

.PHONY: all
all: check

# ── Build and test ──────────────────────────────────────────────────────────────────────────────────────────────────

.PHONY: build
build:
	go build ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	$(GO_TEST_ENV) go test -count=1 ./...

# The client and the protocol share state across goroutines (the key cache, the live pins, the connection pool, a
# batch's parallel seals): the race detector runs over them.
.PHONY: test-race
test-race:
	$(GO_TEST_ENV) go test -race -count=1 . ./internal/... ./wire/... ./cipherontest/... ./peercred/...

# The application-visible surface (testdata/api.txt) is what the code exports: a change to it is a diff of that file.
.PHONY: check-api
check-api:
	$(GO_TEST_ENV) go test -count=1 -run TestThePublicAPI .

.PHONY: update-api
update-api:
	$(GO_TEST_ENV) go test -count=1 -run TestThePublicAPI . -update-api

# go.mod and go.sum are exactly what the code needs.
.PHONY: check-tidy
check-tidy:
	go mod tidy -diff
	go mod verify

# ── Lint and format ─────────────────────────────────────────────────────────────────────────────────────────────────

.PHONY: lint-install
lint-install:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Reports; never rewrites. Never add --fix (see .golangci.yaml). Linux too: the peer-credential code differs by OS.
.PHONY: lint
lint:
	golangci-lint run ./...
	GOOS=linux golangci-lint run ./...

# Formatting only (gci and gofmt): safe to apply.
.PHONY: fmt
fmt:
	golangci-lint fmt ./...

.PHONY: check-fmt
check-fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt: unformatted files:"; echo "$$out"; exit 1; fi

# ── The protocol's own checks ───────────────────────────────────────────────────────────────────────────────────────

# spec/api.md's layout and key tables are generated from the protocol's release and compatibility.md names exactly the
# versions each kind reads (wire/transport/docs_test.go; -update-docs rewrites the blocks); the release follows the
# recorded previous one (wire/transport/release_test.go, format.Check; -update-release once reviewed).
.PHONY: check-format-docs
check-format-docs:
	$(GO_TEST_ENV) go test -count=1 -run 'TestDocs|TestTheDocsChecksRefuse|TestTheReleaseFollowsTheRecordedOne' ./wire/transport/

# The frozen fixtures (spec/frozen) are exactly what HEAD holds: committed, unchanged, nothing beside them. Fails until
# they are committed, by design.
.PHONY: check-golden-fixtures
check-golden-fixtures:
	python3 scripts/checks/check-golden-fixtures.py self-test
	python3 scripts/checks/check-golden-fixtures.py

# Every label is built from the purpose table (wire/format/labels.go).
.PHONY: check-label-namespace
check-label-namespace:
	python3 scripts/checks/check-label-namespace.py --self-test
	python3 scripts/checks/check-label-namespace.py

# AES-GCM draws its IV inside the Go Cryptographic Module (cipher.NewGCMWithRandomNonce).
.PHONY: check-gcm-nonce
check-gcm-nonce:
	python3 scripts/checks/check-gcm-nonce.py --self-test
	python3 scripts/checks/check-gcm-nonce.py

# ── Proto ───────────────────────────────────────────────────────────────────────────────────────────────────────────

.PHONY: install-proto-tools
install-proto-tools:
	@command -v protoc >/dev/null || { echo "protoc is not installed (brew install protobuf; apt-get install protobuf-compiler)" >&2; exit 1; }
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@$(GRPC_GATEWAY_VERSION)
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@$(GRPC_GATEWAY_VERSION)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

# The generated Go (protobuf, gRPC, gRPC-Gateway) and the OpenAPI description, next to the .proto.
.PHONY: proto-gen
proto-gen:
	find proto -type f \( -name '*.pb.go' -o -name '*.pb.gw.go' -o -name '*.swagger.json' \) -delete
	$(PROTO_PATH) protoc -I proto -I third_party/googleapis \
	  --go_out=proto --go_opt=module=$(MODULE)/proto \
	  --go-grpc_out=proto --go-grpc_opt=module=$(MODULE)/proto \
	  --grpc-gateway_out=proto --grpc-gateway_opt=module=$(MODULE)/proto --grpc-gateway_opt=logtostderr=true \
	  --openapiv2_out=proto --openapiv2_opt=logtostderr=true \
	  proto/v1/*.proto
	$(PROTO_PATH) goimports -local $(MODULE) -w proto
	gofmt -w proto

# The committed generated code is what proto-gen writes.
.PHONY: check-proto-gen
check-proto-gen: proto-gen
	@git diff --exit-code -- proto || { echo "proto/: the generated code is not what proto-gen writes (run make proto-gen)" >&2; exit 1; }
	@test -z "$$(git ls-files --others --exclude-standard -- proto)" || { echo "proto/: untracked generated files" >&2; git ls-files --others --exclude-standard -- proto >&2; exit 1; }

# buf, pinned: the buf on PATH is BUF_VERSION, or the recipe stops.
.PHONY: buf-check-version
buf-check-version:
	@got="$$(buf --version 2>/dev/null || true)"; \
	if [ "v$$got" != "$(BUF_VERSION)" ]; then \
	  echo "buf: '$${got:-not installed}' on PATH, expected $(BUF_VERSION) (go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION))" >&2; \
	  exit 1; \
	fi

.PHONY: lint-proto
lint-proto: buf-check-version
	buf format -d --exit-code proto
	buf lint

# The API's wire compatibility against BUF_BASE (a local branch): what CI's proto-breaking job runs against a pull
# request's base. A base without proto/v1 has nothing to break: said, and passed.
BUF_BASE ?= main
.PHONY: check-proto-breaking
check-proto-breaking: buf-check-version
	@if ! git rev-parse --verify --quiet 'refs/heads/$(BUF_BASE)' >/dev/null; then \
	  echo "check-proto-breaking: no local branch '$(BUF_BASE)' (BUF_BASE names the base branch)" >&2; \
	  exit 1; \
	elif [ -z "$$(git ls-tree -d --name-only 'refs/heads/$(BUF_BASE)' -- proto/v1)" ]; then \
	  echo "check-proto-breaking: $(BUF_BASE) has no proto/v1 — nothing to break"; \
	else \
	  buf breaking --against '.git#branch=$(BUF_BASE)' --path proto/v1 && \
	  echo "check-proto-breaking: OK — proto/v1 is wire-compatible with $(BUF_BASE)'s"; \
	fi

# ── Everything ──────────────────────────────────────────────────────────────────────────────────────────────────────

# What CI runs, but the fixture guard (it needs the fixtures committed) and the proto jobs (they need buf and protoc).
.PHONY: check
check: build vet check-fmt check-tidy test check-api check-format-docs check-label-namespace check-gcm-nonce lint
