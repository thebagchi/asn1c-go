# asn1c-go quality gates
#
#   make quick         fmt-check + vet + lint + test-changed  (after every edit)
#   make check         fmt-check + vet + lint + convention + test  (what CI should run)
#   make lint          golangci-lint (bundles staticcheck, errcheck, ineffassign, unused)
#   make convention   the go.md checks no published linter expresses, on every hand-written file
#   make changed       convention on the Go files that differ from HEAD
#   make revision      the new revision.md row names every changed Go file
#   make graph         callers of functions defined in the diff
#   make fold          fold calls, signatures and struct literals to one item a line, on every hand-written file
#   make staticcheck   standalone staticcheck, if its Go version matches the module
#   make race          full test suite under the race detector (about 30 seconds)
#   make regression    just the tests guarding the defects found in review
#   make bin           build cmd/asn1c as tools/bin/asn1c.bin
#   make bench         all benchmarks with memory stats
#   make benchstat     compare two benchmark output files (OLD=old.txt NEW=new.txt)
#   make vuln          govulncheck against the module
#   make toolchain     fetch a pinned Go into .go/, to test against another release
#   make sde           run a program with a CPU feature (SDE_FLAGS=...)
#   make generate      regenerate the AST schema, the goyacc parser and the avo kernels
#   make generate-check fail when go generate ./lib/per/ changes a .s file; the tree stays as it is
#   make catalog       regenerate the instruction catalogue from this toolchain
#   make short         unit tests with -short
#   make test          unit tests; test-changed runs the changed packages only
#   make fmt           rewrite files with gofmt, after fmt-asn1; fmt-check only reports
#   make fmt-asn1      line up the ::= of every ASN.1 module this project owns; fmt-asn1-check only reports
#   make fmt-asn1-test run the unit tests of tools/fmt_asn1/fmt_asn1.py
#   make tidy          go mod tidy, then fail if go.mod or go.sum changed
#   make tools         fetch the pinned tools into the module cache
#   make clean         remove build and profile artefacts
#   make help          list targets
#
# Every linter this file runs is pinned in go.mod as a `tool` directive and runs
# with `go run <module path>`, so the version recorded there is the version used.
# A fresh clone needs no install step and cannot run a different version than CI
# does. No target builds a linter binary. Generators (goyacc, buf, avo,
# protoc-gen-go) are not linters and keep their own invocation.

# Every target takes GO, so a pinned toolchain is used without installing it:
#   make toolchain && make GO=.go/go/bin/go check
GO          ?= go
GO_VERSION  ?= 1.27.3
GO_DIR      ?= .go
# .tools starts with a dot, so ./... skips it. Name cmd and common.
DOT_PKGS    = ./.tools/cmd/... ./.tools/common
PKGS        ?= ./... $(DOT_PKGS)
TEST_FLAGS  ?= -count=1
RACE_TIMEOUT?= 30m
BENCH       ?= .
BENCH_FLAGS ?= -benchmem -run=^$$

# The instruction table "make catalog" reads. Pinned, because a different release
# is a different instruction set and the checked-in catalogue would move under it
# without anything saying why.
ARCH_MODULE ?= golang.org/x/arch@v0.11.0

# Every linter runs from the version pinned in go.mod, through `go run`.
GOLANGCI    ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint
STATICCHECK ?= $(GO) run honnef.co/go/tools/cmd/staticcheck
GOVULNCHECK ?= $(GO) run golang.org/x/vuln/cmd/govulncheck
BENCHSTAT   ?= $(GO) run golang.org/x/perf/cmd/benchstat
CONVENTION  ?= $(GO) run ./.tools/cmd/convention
FOLD        ?= $(GO) run ./.tools/cmd/fold
REVISION    ?= $(GO) run ./.tools/cmd/revision
GRAPH       ?= $(GO) run ./.tools/cmd/graph
# convention and fold read every package. A layout check skips a generated file.
# ./... skips .tools, so name cmd and common here too.
GATE_PKGS ?= ./... $(DOT_PKGS)

# Every hand-written Go file. Generated files (banner on line 1) are dropped: nobody may
# edit one, so a formatter complaint about it is a complaint nobody can act on.
# $(GO_DIR) is excluded as well as .git: a toolchain fetched by "make toolchain"
# puts ten thousand Go files under it, none of them this module's.
# `-r` keeps xargs from running grep with no path, which would read stdin forever.
GO_FILES    := $(shell find . -type f -name '*.go' \
	-not -path './.git/*' -not -path './$(GO_DIR)/*' \
	| xargs -r grep -L '^// Code generated .* DO NOT EDIT\.$$')

# The formatter for ASN.1 modules. It needs only a python3 on the path.
FMT_ASN1    ?= python3 -I tools/fmt_asn1/fmt_asn1.py

# Every ASN.1 module this project writes. The OTP and 3GPP corpora are left out: they are
# copies of another project's text, and a copy that is reformatted no longer diffs against its
# source. Name other files with ASN1_FILES=...
ASN1_FILES  ?= $(shell find . -type f -name '*.asn1' \
	-not -path './.git/*' -not -path './$(GO_DIR)/*' \
	-not -path './compiler/testdata/otp/*' -not -path './testdata/3gpp/*')

# Directories holding Go files that differ from HEAD or are untracked: what `quick` looks at.
CHANGED_DIRS := $(shell { git diff --name-only HEAD -- '*.go'; git ls-files --others --exclude-standard -- '*.go'; } 2>/dev/null | xargs -r -n1 dirname | sort -u)

# `go vet ./...` and `go test ./...` exit 1 when the pattern matches no packages.
# The steps below skip that case.
PACKAGES := $(shell $(GO) list $(PKGS) 2>/dev/null)

.PHONY: all quick check regression fmt fmt-check fmt-asn1 fmt-asn1-check fmt-asn1-test vet lint convention changed revision graph fold staticcheck benchstat test test-changed race short bench vuln tidy tools toolchain sde generate generate-check catalog bin clean help

all: check

## check: run every gate that should block a merge
check: fmt-check vet lint convention test

## quick: the after-every-edit gate; tests limited to what changed
quick: fmt-check vet lint test-changed

## fmt: format the ASN.1 modules, then rewrite files with gofmt and spell the escape hatch 'any'
fmt: fmt-asn1
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

## fmt-asn1: rewrite the ASN.1 modules so that the ::= of each block of assignments stands in one column
fmt-asn1:
	@test -z "$(ASN1_FILES)" || $(FMT_ASN1) -w $(ASN1_FILES)

## fmt-asn1-check: fail if an ASN.1 module is not formatted, and list it
fmt-asn1-check:
	@echo "==> fmt_asn1              $(words $(ASN1_FILES)) file(s)"
	@test -z "$(ASN1_FILES)" || $(FMT_ASN1) -l $(ASN1_FILES)

## fmt-asn1-test: run the unit tests of the ASN.1 formatter
fmt-asn1-test:
	python3 -I -m unittest discover -s tools/fmt_asn1 -p '*_test.py' -v

## vet: go vet
vet:
	@test -z "$(PACKAGES)" || $(GO) vet $(PKGS)

## lint: golangci-lint (includes a current staticcheck)
lint:
	@test -z "$(PACKAGES)" || $(GOLANGCI) run $(PKGS)

## convention: the checks in go.md that no published linter expresses
convention:
	@echo "==> convention            $(GATE_PKGS)"
	@test -z "$(PACKAGES)" || $(CONVENTION) $(GATE_PKGS)

## changed: convention on the Go files that differ from HEAD
changed:
	@echo "==> convention -changed"
	@$(CONVENTION) -changed

## revision: the new revision.md row names every changed Go file
revision:
	@echo "==> revision"
	@$(REVISION)

## graph: callers of the functions defined in the diff
graph:
	@echo "==> graph -changed"
	@$(GRAPH) -changed

## fold: fold calls, signatures and struct literals to one item a line (convention call, literal)
fold:
	@test -z "$(PACKAGES)" || $(FOLD) -w $(GATE_PKGS)

## staticcheck: staticcheck on its own, beyond the copy inside golangci-lint
#
# Pinned as a tool, so it is built with this module's toolchain. An installed binary
# refuses a module whose go directive is newer than the Go it was compiled with, which
# is what made this target unusable before.
staticcheck:
	@test -z "$(PACKAGES)" || $(STATICCHECK) $(PKGS)

## test: unit tests (no race detector)
test:
	@test -z "$(PACKAGES)" || $(GO) test $(TEST_FLAGS) $(PKGS)

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
	@test -z "$(PACKAGES)" || $(GO) test $(TEST_FLAGS) -short $(PKGS)

## race: unit tests under the race detector
race:
	@test -z "$(PACKAGES)" || $(GO) test $(TEST_FLAGS) -race -timeout $(RACE_TIMEOUT) $(PKGS)

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

## benchstat: compare two benchmark output files
benchstat:
	$(BENCHSTAT) $(OLD) $(NEW)

## vuln: govulncheck against the module
vuln:
	@test -z "$(PACKAGES)" || $(GOVULNCHECK) $(PKGS)

## tidy: go mod tidy and verify nothing changed
tidy:
	$(GO) mod tidy
	@git diff --exit-code -- go.mod go.sum || { echo "go.mod/go.sum changed; commit the result"; exit 1; }

## tools: fetch the pinned tools into the module cache (a fresh clone needs only this)
tools:
	$(GO) mod download
	$(GOLANGCI) --version

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

## generate-check: fail when go generate ./lib/per/ changes an assembly file
#
# The kernels of lib/per are generated by lib/per/gen. This runs that generator
# as go generate does, compares each .s file with the copy taken before the run,
# and then puts every copy back, so the files in the tree do not change. A file
# that differs names a generator and a .s file that are no longer in step.
generate-check:
	@saved=$$(mktemp -d) && \
	trap 'cp "$$saved"/*.s lib/per/ && rm -rf "$$saved"' EXIT && \
	cp lib/per/*.s "$$saved"/ && \
	$(GO) generate ./lib/per/ && \
	status=0 && \
	for file in "$$saved"/*.s; do \
		name=$$(basename "$$file"); \
		cmp -s "$$file" "lib/per/$$name" || { echo "generate-check: lib/per/$$name changes"; status=1; }; \
	done; \
	exit $$status

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

## sde: run a program with a CPU feature, under SDE when this CPU lacks it
#
# SDE_FLAGS are the flags of .tools/cmd/sde. The kit is the Intel Simplified
# Software License. The command fetches it, and it is not committed.
#   make sde
#   make sde SDE_FLAGS='-feature avx512 -- go test ./lib/bitbuffer -count=1 -run TestName'
#   make sde SDE_FLAGS='-feature avx512 -count -- go test ./lib/bitbuffer -bench . -count=1'
sde:
	$(GO) run ./.tools/cmd/sde $(SDE_FLAGS)

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
