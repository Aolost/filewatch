GO       ?= go
GOFMT    ?= gofmt
FUZZTIME ?= 10s

# Everything runs offline: no module downloads, no toolchain downloads.
export GOPROXY     := off
export GOTOOLCHAIN := local
export GOFLAGS     := -mod=readonly
export CGO_ENABLED := 1

FUZZ_TARGETS := \
	./internal/indicators:FuzzParse \
	./internal/heuristics:FuzzCheck \
	./internal/report:FuzzSafeText \
	./internal/scan:FuzzScanName

.PHONY: check fmt-check vet test race fuzz build clean

check: fmt-check vet race fuzz
	@echo "make check: OK"

build:
	$(GO) build -trimpath -o bin/filewatch ./cmd/filewatch

fmt-check:
	@out="$$($(GOFMT) -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

# Repository hygiene (no raw bidi controls, no executable-looking files) is
# enforced by internal/repocheck, a portable Go test run by "race" below.

test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; fn=$${t##*:}; \
		echo "fuzz $$fn ($(FUZZTIME))"; \
		$(GO) test -run='^$$' -fuzz="^$$fn$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
	done

clean:
	rm -rf bin
