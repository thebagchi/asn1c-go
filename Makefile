# asn1c-go quality gates
#
#   make quick         fmt-check + vet + lint-new + test-changed  (after every edit)
#   make check         fmt-check + vet + lint + test          (what CI should run)
#   make lint          golangci-lint (bundles staticcheck, errcheck, ineffassign, unused)
#   make staticcheck   standalone staticcheck, if its Go version matches the module
#   make race          full test suite under the race detector (about 30 seconds)
#   make regression    just the tests guarding the defects found in review
#   make bin           build cmd/asn1c as tools/bin/asn1c.bin
#   make bench         all benchmarks with memory stats
#   make vuln          govulncheck against the module
#   make toolchain     fetch a pinned Go into .go/, to test against another release
#   make generate      regenerate the AST schema, the goyacc parser and the avo kernels
#   make catalog       regenerate the instruction catalogue from this toolchain
#
# Every tool this file runs is pinned in go.mod as a `tool` directive, so `go tool
# <name>` builds it from the version recorded there. A fresh clone needs no install
# step and cannot run a different version than CI does.

# Every target takes GO, so a pinned toolchain is used without installing it:
#   make toolchain && make GO=.go/go/bin/go check
GO          ?= go
GO_VERSION  ?= 1.27.1
GO_DIR      ?= .go
PKGS        ?= ./...
TEST_FLAGS  ?= -count=1
RACE_TIMEOUT?= 30m
BENCH       ?= .
BENCH_FLAGS ?= -benchmem -run=^$$

# The instruction table "make catalog" reads. Pinned, because a different release
# is a different instruction set and the checked-in catalogue would move under it
# without anything saying why.
ARCH_MODULE ?= golang.org/x/arch@v0.11.0

# Every hand-written Go file. Generated files (banner on line 1) are dropped: nobody may
# edit one, so a formatter complaint about it is a complaint nobody can act on.
# $(GO_DIR) is excluded as well as .git: a toolchain fetched by "make toolchain"
# puts ten thousand Go files under it, none of them this module's.
GO_FILES    := $(shell find . -type f -name '*.go' \
	-not -path './.git/*' -not -path './$(GO_DIR)/*' \
	| xargs grep -L '^// Code generated .* DO NOT EDIT\.$$')

# Directories holding Go files that differ from HEAD or are untracked: what `quick` looks at.
CHANGED_DIRS := $(shell { git diff --name-only HEAD -- '*.go'; git ls-files --others --exclude-standard -- '*.go'; } 2>/dev/null | xargs -r -n1 dirname | sort -u)

.PHONY: all quick check regression fmt fmt-check vet lint lint-new staticcheck test test-changed race short bench vuln tidy tools toolchain generate catalog bin clean help

all: check

## check: run every gate that should block a merge
check: fmt-check vet lint test

## quick: the after-every-edit gate; lint and tests limited to what changed
quick: fmt-check vet lint-new test-changed

## fmt: rewrite files with gofmt, and spell the escape hatch 'any'
fmt:
	gofmt -w -l $(GO_FILES)
	gofmt -w -l -r 'interface{} -> any' $(GO_FILES)

## fmt-check: fail if any file is not gofmt-clean or spells 'interface{}'
fmt-check:
	@echo "==> gofmt                 $(words $(GO_FILES)) file(s)"
	@out="$$(gofmt -l $(GO_FILES))"; \
	if [ -n "$$out" ]; then echo "gofmt would rewrite:"; echo "$$out"; exit 1; fi
	@echo "==> interface{} -> any    $(words $(GO_FILES)) file(s)"
	@out="$$(gofmt -l -r 'interface{} -> any' $(GO_FILES))"; \
	if [ -n "$$out" ]; then echo "spell the escape hatch 'any', not 'interface{}':"; echo "$$out"; exit 1; fi

## vet: go vet
vet:
	$(GO) vet $(PKGS)

## lint: golangci-lint (includes a current staticcheck)
lint:
	$(GO) tool golangci-lint run $(PKGS)

## lint-new: golangci-lint on uncommitted changes only (or HEAD~ when the tree is clean)
lint-new:
	@echo "==> golangci-lint --new  (uncommitted changes)"
	$(GO) tool golangci-lint run --new $(PKGS)

## staticcheck: staticcheck on its own, beyond the copy inside golangci-lint
#
# Pinned as a tool, so it is built with this module's toolchain. An installed binary
# refuses a module whose go directive is newer than the Go it was compiled with, which
# is what made this target unusable before.
staticcheck:
	$(GO) tool staticcheck $(PKGS)

## test: unit tests (no race detector)
test:
	$(GO) test $(TEST_FLAGS) $(PKGS)

## test-changed: tests for packages with changed files, plus every package that imports them
test-changed:
	@dirs="$(CHANGED_DIRS)"; \
	if [ -z "$$dirs" ]; then echo "==> go test: no changed Go files"; exit 0; fi; \
	pkgs=""; for d in $$dirs; do p=$$($(GO) list -e ./$$d 2>/dev/null) && pkgs="$$pkgs $$p"; done; \
	rdeps=$$($(GO) list -e -f '{{.ImportPath}}{{range .Deps}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}' $(PKGS) \
		| awk -v want="$$pkgs" 'BEGIN{n=split(want,w," ")} { for(i=1;i<=n;i++) if (index(" "$$0" ", " "w[i]" ")) { print $$1; break } }'); \
	all=$$(printf '%s\n' $$pkgs $$rdeps | sort -u | tr '\n' ' '); \
	echo "==> go test $(TEST_FLAGS): $$all"; \
	$(GO) test $(TEST_FLAGS) $$all

## short: unit tests with -short (once long loops are gated behind testing.Short)
short:
	$(GO) test $(TEST_FLAGS) -short $(PKGS)

## race: unit tests under the race detector
race:
	$(GO) test $(TEST_FLAGS) -race -timeout $(RACE_TIMEOUT) $(PKGS)

## regression: the tests guarding the defects found in review (lib/review.md)
#
# Every package, not ./lib/... - the defects recorded in review are not only
# the runtime library's, and a regression test written anywhere has to run.
# -run filters, so naming more packages costs nothing.
regression:
	$(GO) test $(TEST_FLAGS) -race -timeout 5m -run 'TestRegression' ./...

## bin: build the compiler; every binary carries an extension (CLAUDE.md, Build)
bin:
	$(GO) build -o tools/bin/asn1c.bin ./cmd/asn1c

## bench: run benchmarks (override with BENCH=ReadBytesMisaligned)
bench:
	$(GO) test $(BENCH_FLAGS) -bench '$(BENCH)' $(PKGS)

## vuln: govulncheck against the module
vuln:
	$(GO) tool govulncheck $(PKGS)

## tidy: go mod tidy and verify nothing changed
tidy:
	$(GO) mod tidy
	@git diff --exit-code -- go.mod go.sum || { echo "go.mod/go.sum changed; commit the result"; exit 1; }

## tools: fetch the pinned tools into the module cache (a fresh clone needs only this)
tools:
	$(GO) mod download
	$(GO) tool golangci-lint --version

## generate: rerun the code generators, then check the tree still builds
#
# Generated files are never edited and never linted; each carries the banner on
# its first line, which is what the gates key off.
#
# ./proto is first: it writes ast/ast.pb.go, which compiler/ reads. buf and
# protoc-gen-go are both Go and both pinned as tool directives, so this needs
# no protoc and nothing installed outside the module.
#
# ./specs is deliberately not in the list: its generator downloads the ITU-T
# documents and drives libreoffice, which needs a network and several minutes.
# Run "go generate ./specs/" by hand when the specifications change.
generate:
	$(GO) generate ./proto/
	$(GO) generate ./lib/... ./compiler/...
	$(GO) build ./...

## catalog: regenerate the instruction catalogue under tools/simd/catalog
#
# It reads the assembler's own tables out of GOROOT, so it describes whichever
# toolchain runs it. golang.org/x/arch supplies the Intel and ARM spellings and
# the arm64 bit patterns; it is downloaded rather than required, and read as data
# files rather than imported, so this module keeps its no-dependency property.
catalog:
	$(GO) mod download $(ARCH_MODULE)
	$(GO) run tools/simd/catalog/main.go \
		-out tools/simd/catalog \
		-arch "$$($(GO) env GOMODCACHE)/$(ARCH_MODULE)"
	$(GO) test ./tools/simd/catalog/

## toolchain: download a pinned Go into .go/, for testing against another release
#
# The SIMD experiment is the reason this exists: it needs GOEXPERIMENT=simd and
# a release newer than the system one. .claude/finding.md records what it found.
toolchain:
	@mkdir -p $(GO_DIR)
	@test -x $(GO_DIR)/go/bin/go || { \
		echo "==> downloading go$(GO_VERSION)"; \
		curl -fsSL https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz \
			-o $(GO_DIR)/go.tar.gz && \
		tar -xzf $(GO_DIR)/go.tar.gz -C $(GO_DIR) && \
		rm -f $(GO_DIR)/go.tar.gz; }
	@$(GO_DIR)/go/bin/go version

## clean: remove build and profile artefacts
clean:
	$(GO) clean -testcache
	rm -f *.test *.out coverage.* profile.cov
	rm -rf tools/bin

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
