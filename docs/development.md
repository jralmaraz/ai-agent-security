# Development Guide

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Go | 1.26+ | [go.dev/dl](https://go.dev/dl/) or `brew install go` |
| govulncheck | v1.6.0 | `go install golang.org/x/vuln/cmd/govulncheck@v1.6.0` |
| Python 3 | any | For the local demo HTTP server |

---

## First-time setup

```bash
git clone https://github.com/jralmaraz/wimse-agent-fabric
cd wimse-agent-fabric

# Install the pre-push quality gate (runs the same checks as CI)
make hooks
```

---

## Common tasks

```bash
# Run all tests (race detector enabled)
make test

# Run all CI gates locally (vet + test + govulncheck)
make check

# Run a single test
go test ./pkg/identity/... -v -run TestAgentChain_Validate

# Build the gateway binary
go build -o bin/gateway ./cmd/gateway

# Build the browser demo
make wasm

# Serve the demo locally
cd demo && python3 -m http.server 8000
# → http://localhost:8000
```

---

## Project conventions

### Module path

```
github.com/jralmaraz/wimse-agent-fabric
```

All internal imports must use this full module path.

### Packages

| Visibility | Rule |
|---|---|
| `pkg/` | Stable public API — no internal dependencies |
| `internal/` | Implementation packages — may import `pkg/` but not vice versa |
| `cmd/` | Runnable binaries — import both `pkg/` and `internal/` |

### Error handling

All errors are wrapped with `fmt.Errorf("context: %w", err)`. Functions that cannot fail deterministically (e.g., `encodeCoord`) may `panic` on CSPRNG failure — this matches the stdlib convention for crypto operations.

### JWT signing

All tokens use ES256 (EC P-256). Do not add RSA or HMAC paths. The `alg` field in JWKs is always `"ES256"`.

### Coordinate encoding

JWK `x` and `y` values are always left-padded to exactly 32 bytes before base64url encoding. See `pkg/keys.encodeCoord`.

---

## Writing tests

Tests live alongside source files in `_test.go` files using the `_test` package suffix (external test packages). This enforces that tests only use the public API.

```go
// pkg/identity/identity_test.go
package identity_test

import "github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
```

### Test naming

Follow the pattern `Test<Type>_<Scenario>`:

```go
func TestAgentToken_HappyPath(t *testing.T)
func TestAgentToken_Expired(t *testing.T)
func TestAgentChain_WrongDepthOrder(t *testing.T)
func TestGateway_ReplayAttack(t *testing.T)
```

### Gateway tests

The gateway uses a real `httptest.Server` for any test that exercises the reverse proxy. This avoids a panic caused by `httputil.ReverseProxy` requiring `http.CloseNotifier`, which `httptest.ResponseRecorder` does not implement:

```go
// Correct: real server for proxy tests
gwServer := httptest.NewServer(gw)
defer gwServer.Close()
resp, _ := http.DefaultClient.Do(req)

// OK: ResponseRecorder for auth-rejection tests (never reaches the proxy)
w := httptest.NewRecorder()
gw.ServeHTTP(w, req) // returns 401/403 before proxy is invoked
```

### Proof token URI in tests

The request URI in the proof token `aud` must match what the gateway middleware reconstructs. When using `httptest.NewServer` (HTTP, not HTTPS):

```go
// The gateway builds: "http://" + host + path
target := gwServer.URL + "/tools/echo/hello"  // e.g. "http://127.0.0.1:54321/tools/echo/hello"

// Use the same string when generating the proof
proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
    TargetURI:   target,  // must match exactly
    ...
})

// And as the HTTP request target
req, _ := http.NewRequest("GET", target, nil)
```

---

## Dependency management

```bash
# Add a new dependency
go get github.com/some/package@v1.2.3
go mod tidy

# Check for vulnerabilities after upgrading
govulncheck ./...
```

`govulncheck` is pinned to `v1.6.0` in both CI and the pre-push hook to avoid database drift. Do not change this version without updating both `.github/workflows/ci.yml` and `.githooks/pre-push`.

### quic-go pinning

`github.com/quic-go/quic-go` is an indirect dependency pulled in by `openfga/go-sdk`. It must be pinned at `v0.59.1` or later (v0.59.0 has GO-2026-5676, an HTTP/3 QPACK memory exhaustion vuln). If `go mod tidy` downgrades it:

```bash
go get github.com/quic-go/quic-go@v0.59.1
go mod tidy
```

---

## CI pipeline

```
push/PR to main
│
├── test job (ubuntu-latest)
│   ├── go mod verify
│   ├── go vet ./...
│   ├── go test ./... -v -count=1 -race -timeout 120s
│   └── govulncheck ./...  (pinned v1.6.0)
│
├── security job (main pushes only, needs: test)
│   ├── go build → binary for SBOM scanning
│   ├── anchore/sbom-action → sbom.spdx.json
│   ├── anchore/scan-action → grype.sarif
│   └── upload-sarif → GitHub Security tab
│
└── deploy-demo job (main pushes only, needs: test)
    ├── GOOS=js GOARCH=wasm go build ./cmd/demo-wasm/
    ├── copy wasm_exec.js from GOROOT
    └── deploy to GitHub Pages
```

The pre-push hook mirrors the `test` job exactly. If the hook passes, CI will pass (assuming no environment differences).

---

## Adding a new tool route

1. Register an authorization rule:

```go
a.Allow("spiffe://example/orch", "tool:my-new-tool", authz.ActionCall)
```

2. Add the route to the gateway config:

```go
Routes: map[string]string{
    "tool:my-new-tool": "http://my-tool-service:9095",
},
```

The gateway automatically creates the `/tools/my-new-tool/*` route group with the full auth middleware chain applied.

---

## Adding a new trust domain / IdP

Register an additional validator:

```go
Validators: map[string]*identity.AgentValidator{
    "https://idp.cloud-a.example": identity.NewAgentValidator(
        "https://idp.cloud-a.example", cloudAPublicKey,
    ),
    "https://idp.cloud-b.example": identity.NewAgentValidator(  // new
        "https://idp.cloud-b.example", cloudBPublicKey,
    ),
},
```

The gateway and `AgentChain.Validate` both accept a `map[issuerID]*AgentValidator`. Tokens from either IdP will be accepted. Chains may mix tokens from different IdPs (useful for cross-domain delegation flows).
