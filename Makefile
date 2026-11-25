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

.PHONY: check fmt-check vet source-check test race fuzz build clean

check: fmt-check vet source-check race fuzz
	@echo "make check: OK"

build:
	$(GO) build -trimpath -o bin/filewatch ./cmd/filewatch

fmt-check:
	@out="$$($(GOFMT) -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

# Reject invisible bidi controls in sources ("Trojan Source") and any file
# that looks like an executable sample; fixtures must be generated text.
source-check:
	@if grep -rlP '[\x{202A}-\x{202E}\x{2066}-\x{2069}]' --include='*.go' --include='*.md' --include='*.txt' . ; then \
		echo "raw bidirectional control characters found (use \\u escapes)"; exit 1; fi
	@bad=$$(find . -path ./.git -prune -o -path ./bin -prune -o -type f -print | while read -r f; do \
		h=$$(head -c 4 "$$f" | od -An -tx1 | tr -d ' \n'); \
		case "$$h" in 7f454c46*|4d5a*|feedface|feedfacf|cefaedfe|cffaedfe) echo "$$f";; esac; done); \
	if [ -n "$$bad" ]; then echo "executable-looking files in repository:"; echo "$$bad"; exit 1; fi

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
