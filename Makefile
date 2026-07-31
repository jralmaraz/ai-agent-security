GOVULNCHECK_VERSION := v1.6.0

.PHONY: all check test vet verify vulncheck tidy wasm clean hooks

all: check

## check — runs every gate that CI runs on push/PR
check: verify vet test vulncheck

## verify — module checksum integrity
verify:
	go mod verify

## vet — static analysis
vet:
	go vet ./...

## test — full test suite with race detector
test:
	go test ./... -v -count=1 -race -timeout 120s

## vulncheck — vulnerability scan pinned to same version as CI
vulncheck:
	@which govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	govulncheck ./...

## tidy — ensure go.mod and go.sum are tidy
tidy:
	go mod tidy

## wasm — build the browser demo WASM binary
wasm:
	GOOS=js GOARCH=wasm go build -o demo/wimse-agent.wasm ./cmd/demo-wasm/
	@GOROOT=$$(go env GOROOT); \
	if [ -f "$$GOROOT/lib/wasm/wasm_exec.js" ]; then \
		cp "$$GOROOT/lib/wasm/wasm_exec.js" demo/wasm_exec.js; \
	else \
		cp "$$GOROOT/misc/wasm/wasm_exec.js" demo/wasm_exec.js; \
	fi
	@echo "WASM built. Run: cd demo && python3 -m http.server 8000"

## hooks — activate the pre-push git hook for this clone (run once after cloning)
hooks:
	git config core.hooksPath .githooks
	@echo "Git pre-push hook enabled."

## clean — remove generated WASM artifacts
clean:
	rm -f demo/wimse-agent.wasm demo/wasm_exec.js
