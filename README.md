# AI Agent Security

**Proof-of-concept: cryptographic identity and authorization for multi-hop AI agent workloads**

[![CI](https://github.com/jralmaraz/ai-agent-security/actions/workflows/ci.yml/badge.svg)](https://github.com/jralmaraz/ai-agent-security/actions/workflows/ci.yml)
[![Go 1.26](https://img.shields.io/badge/go-1.26-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Live demo:** https://ai-agent-security-cgt.pages.dev/

---

## What this is

Modern AI systems run as pipelines of collaborating agents: an **Orchestrator** decomposes a task and dispatches work to **Executor** agents, which call **Tool Servers** (weather APIs, databases, code runners, etc.). Securing these multi-hop calls is hard — a tool server receiving a request needs to know:

- *Who* started the chain? (the orchestrator)
- *Who* is making this specific call? (the executor, acting on the orchestrator's behalf)
- *Is the full delegation path legitimate?*
- *Can this request be proved fresh and bound to this specific target?*

This PoC implements cryptographic identity and authorization across a multi-hop agent pipeline, using emerging standards from the IETF (WIMSE WG, OAuth WG) and OpenID Foundation. Each hop carries a signed **AgentToken** (`agent+jwt`) with a `chain_depth` counter. A per-request **AgentProofToken** (`application/agent-proof+jwt`) binds the call to the exact target URI and the full delegation chain, preventing replay and audience-confusion attacks. An **Agent Gateway** (MCP-compatible HTTP proxy) validates the entire chain before forwarding to any tool.

This is a research PoC — not production software. It is intended to illustrate the design space and serve as a concrete starting point for standardisation discussion.

---

## Quick start

```bash
# Prerequisites: Go 1.26+
git clone https://github.com/jralmaraz/ai-agent-security
cd ai-agent-security

# Activate the pre-push quality gate (run once after cloning)
make hooks

# Run the full test suite
make test

# Run all CI quality gates locally (vet + test + govulncheck)
make check
```

Interactive browser demo (no server required beyond a static file server):

```bash
make wasm          # builds demo/agent.wasm and copies wasm_exec.js
cd demo && python3 -m http.server 8000
# Open http://localhost:8000
```

Run the gateway with mTLS (auto-generates ephemeral CA):

```bash
# Start gateway in mTLS mode — writes demo agent cert/key to /tmp/agent-*.pem
go run ./cmd/gateway --mtls --trust-domain agents.example \
    --write-agent-creds /tmp/agent --port 8443

# CA cert is logged to stdout; also written to /tmp/agent-ca.pem
# Agent cert → /tmp/agent-agent.pem
# Agent key  → /tmp/agent-agent-key.pem (mode 0600)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Trust Domain                            │
│                                                                 │
│   ┌─────────┐   AgentToken (AT-1)   ┌────────────────────────┐ │
│   │   IdP   │──────────────────────►│  Orchestrator Agent    │ │
│   │         │   AgentToken (AT-2)   │  sub: spiffe://.../orch │ │
│   │  ES256  │──────────────────────►│  role: orchestrator    │ │
│   └─────────┘                       │  chain_depth: 0        │ │
│                                     └──────────┬─────────────┘ │
│                                                │ delegates      │
│                                                │ AT-1~AT-2      │
│                                                ▼               │
│                                     ┌────────────────────────┐ │
│                                     │   Executor Agent       │ │
│                                     │   role: executor       │ │
│                                     │   chain_depth: 1       │ │
│                                     └──────────┬─────────────┘ │
│                                                │               │
│                     Agent-Identity-Token: AT-2 │               │
│                     Agent-Chain-Token: AT-1~AT-2│              │
│                     Agent-Proof-Token: APT      │               │
│                                                ▼               │
│                                     ┌────────────────────────┐ │
│                                     │  Agent Gateway         │ │
│                                     │  (MCP-compatible proxy)│ │
│                                     │                        │ │
│                                     │  1. validate AT-2 sig  │ │
│                                     │  2. validate chain     │ │
│                                     │  3. validate APT sig   │ │
│                                     │  4. check aud/hash     │ │
│                                     │  5. authz check        │ │
│                                     └──────────┬─────────────┘ │
│                                                │ forward        │
│                                                ▼               │
│                                     ┌────────────────────────┐ │
│                                     │   Tool Server          │ │
│                                     │   (weather, DB, etc.)  │ │
│                                     └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Token types

| Token | JWT `typ` | Signed by | Lifetime | Purpose |
|---|---|---|---|---|
| **AgentToken** | `agent+jwt` | IdP (ES256) | configurable (default 1 h) | Identity + role + chain position |
| **AgentProofToken** | `application/agent-proof+jwt` | Agent workload (ES256) | 5 min | Per-request proof-of-possession |

### HTTP headers

```
Agent-Identity-Token: <compact AgentToken JWT for this hop>
Agent-Chain-Token:    AT-1~AT-2~...~AT-N   (full delegation chain)
Agent-Proof-Token:    <compact AgentProofToken JWT>
```

---

## Project layout

```
ai-agent-security/
├── pkg/
│   ├── keys/
│   │   ├── ec.go           EC P-256 key generation, JWK (de)serialization
│   │   ├── mtls.go         CA generation, agent cert issuance, TLS config helpers
│   │   └── ec_test.go / mtls_test.go
│   └── identity/
│       ├── token.go        AgentToken: AgentIssuer, AgentValidator, AgentClaims
│       ├── chain.go        AgentChain: wire format, sequential-depth validation
│       ├── proof.go        AgentProofToken: GenerateProof, ProofValidator
│       ├── helpers.go      JTI generation (crypto/rand)
│       └── identity_test.go
├── internal/
│   ├── authz/
│   │   ├── authz.go        Authorizer interface, InMemoryAuthorizer, OpenFGAAuthorizer
│   │   ├── middleware.go   Gin middleware: AgentAuth (identity + chain + proof + authz)
│   │   └── authz_test.go
│   └── gateway/
│       ├── server.go       MCP-compatible HTTP reverse proxy (+ mTLS cert binding)
│       ├── multivalidator.go  Multi-IdP token validation
│       ├── gateway_test.go
│       └── mtls_test.go    mTLS end-to-end tests (happy path, wrong CA, SAN mismatch, no cert)
├── cmd/
│   ├── gateway/main.go     Runnable gateway binary
│   └── demo-wasm/main.go   Browser demo (WASM entry point)
├── demo/
│   └── index.html          Interactive browser demo
├── .github/
│   ├── workflows/ci.yml    GitHub Actions: test / SBOM+vulnscan / deploy demo
│   └── dependabot.yml      Automated dependency updates
├── .githooks/pre-push      Local quality gate (mirrors CI exactly)
└── Makefile
```

---

## Core concepts

### AgentToken (`agent+jwt`)

An `AgentToken` is a signed JWT issued by an Identity Provider. It identifies one agent workload at one hop of a delegation chain.

**Claims:**

```jsonc
{
  "iss": "https://idp.agent-fabric.example",   // IdP issuer URI
  "sub": "spiffe://cloud-a.example/orch",       // agent SPIFFE URI
  "aud": ["https://gateway.example"],
  "exp": 1753999200,
  "iat": 1753995600,
  "jti": "Xk9mP3...",                           // unique token ID
  "role": "orchestrator",                        // orchestrator | executor | tool-server
  "chain_depth": 0,                              // 0-indexed hop position
  "cnf": {
    "jwk": {                                     // agent's own EC P-256 public key
      "kty": "EC", "crv": "P-256",
      "x": "...", "y": "...", "alg": "ES256"
    }
  }
}
```

**Validation checks:** ES256 signature, `exp`/`nbf`/`iat`, `typ: agent+jwt`, issuer match.

### AgentChain wire format

The full delegation history is transmitted as a `~`-separated string of compact JWTs:

```
AT-1~AT-2~...~AT-N
```

The gateway validates that:
- every token has a valid signature, expiry, and `typ`
- `chain_depth` values are strictly sequential (0, 1, 2, …)
- no gaps or resets in depth are present

### AgentProofToken (`application/agent-proof+jwt`)

A per-request proof signed by the calling agent's own private key (the key bound into the AgentToken via `cnf.jwk`).

**Claims:**

```jsonc
{
  "aud": ["https://tool-server.example/api/weather"],  // exact target URI
  "exp": 1753995900,
  "iat": 1753995600,
  "jti": "aB3zR7...",                                  // for replay detection
  "chain_hash": "base64url(SHA-256(AT-1~AT-2~...~AT-N))"
}
```

**Validation checks:** ES256 signature (using key from `cnf.jwk`), `exp`, `aud == requestURI`, `chain_hash` matches presented chain, `jti` not seen before.

### Authorization model

The gateway enforces a `subject × object × action` authorization check on every request:

| Action | Implies |
|---|---|
| `can_call` | `can_call`, `can_read` |
| `can_write` | `can_write`, `can_read` |
| `can_read` | `can_read` |

`InMemoryAuthorizer` is used for development and tests. `OpenFGAAuthorizer` connects to an [OpenFGA](https://openfga.dev/) server (open-source Zanzibar) for production use.

---

## API reference

### `pkg/keys`

```go
// GenerateECKeyPair generates a fresh EC P-256 key pair.
func GenerateECKeyPair() (*ECKeyPair, error)

// PublicKeyToJWK serializes a public key to a JWK.
// X and Y are left-padded to 32 bytes (RFC 7518 §6.2).
func PublicKeyToJWK(pub *ecdsa.PublicKey, kid string) (*JWK, error)

// JWKToPublicKey deserializes a JWK back to an *ecdsa.PublicKey.
// Returns an error if the point is not on the P-256 curve.
func JWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error)

// JWKFromRawMessage parses a json.RawMessage into a JWK.
func JWKFromRawMessage(raw json.RawMessage) (*JWK, error)
```

### `pkg/identity` — AgentToken

```go
// NewAgentIssuer creates an issuer. issuerID must be an absolute URI.
func NewAgentIssuer(issuerID string, sigKey *ecdsa.PrivateKey, ttl time.Duration) *AgentIssuer

// Issue mints a signed AgentToken JWT.
func (i *AgentIssuer) Issue(opts IssueOptions) (string, error)

// IssueOptions controls token content.
type IssueOptions struct {
    Subject     string          // SPIFFE URI (e.g. spiffe://trust-domain/workload)
    Audiences   []string
    Role        string          // RoleOrchestrator | RoleExecutor | RoleToolServer
    ChainDepth  int             // 0 = originating orchestrator
    KeyID       string          // optional kid header
    WorkloadKey *ecdsa.PublicKey // agent's key → cnf.jwk
}

// NewAgentValidator creates a validator for tokens from a specific IdP.
func NewAgentValidator(issuerID string, idpPub *ecdsa.PublicKey, opts ...jwt.ParserOption) *AgentValidator

// Validate verifies signature, expiry, issuer, typ, and extracts cnf.jwk.
func (v *AgentValidator) Validate(token string) (*ValidatedAgent, error)

type ValidatedAgent struct {
    Claims      *AgentClaims
    WorkloadKey *ecdsa.PublicKey // extracted from cnf.jwk
}
```

### `pkg/identity` — AgentChain

```go
// ParseChain parses the AT-1~AT-2~...~AT-N wire format.
func ParseChain(s string) (AgentChain, error)

// String returns the wire-format string.
func (c AgentChain) String() string

// Extend appends a token and returns a new chain (original is not modified).
func (c AgentChain) Extend(token string) (AgentChain, error)

// Hash returns base64url(SHA-256(wire string)) — used in chain_hash.
func (c AgentChain) Hash() string

// Validate validates every token in the chain and enforces sequential chain_depth.
// validators is keyed by issuer ID to support multi-IdP chains.
func (c AgentChain) Validate(validators map[string]*AgentValidator) ([]*ValidatedAgent, error)
```

### `pkg/identity` — AgentProofToken

```go
// GenerateProof creates a signed AgentProofToken.
func GenerateProof(opts ProofGenerateOptions) (string, error)

type ProofGenerateOptions struct {
    TargetURI   string           // becomes aud
    Chain       AgentChain       // used for chain_hash
    WorkloadKey *ecdsa.PrivateKey // agent's private key
    TTL         time.Duration    // 0 = default 5 min
}

// NewProofValidator creates a validator with its own JTI replay store.
func NewProofValidator() *ProofValidator

// Validate verifies the proof token against the chain and request URI.
func (v *ProofValidator) Validate(opts ProofValidateOptions) (*AgentProofClaims, error)

type ProofValidateOptions struct {
    ProofToken  string
    Chain       AgentChain
    RequestURI  string           // must match aud
    WorkloadKey *ecdsa.PublicKey // from AgentToken cnf.jwk
    CheckReplay bool             // enable JTI deduplication
}
```

### `internal/authz`

```go
// Authorizer is the interface for all authorization backends.
type Authorizer interface {
    Authorize(ctx context.Context, req Request) (Decision, error)
}

// InMemoryAuthorizer — development / testing
a := authz.NewInMemoryAuthorizer()
a.Allow("spiffe://x/orchestrator", "tool:weather", authz.ActionCall)
a.Allow("*", "tool:public-info", authz.ActionRead) // wildcard subject

// OpenFGAAuthorizer — production
a, err := authz.NewOpenFGAAuthorizer(authz.OpenFGAConfig{
    APIURL:  "http://openfga:8080",
    StoreID: "my-store-id",
})
```

### `internal/gateway`

```go
gw := gateway.New(gateway.Config{
    // Map of issuerID → AgentValidator (supports multi-IdP trust)
    Validators: map[string]*identity.AgentValidator{
        "https://idp.example": validator,
    },
    // One ProofValidator per gateway instance (owns the JTI replay store)
    ProofValidator: identity.NewProofValidator(),
    // Authorization backend
    Authz: authz.NewInMemoryAuthorizer(),
    // Map of tool name → upstream base URL
    Routes: map[string]string{
        "tool:weather-api": "http://weather-service:9090",
        "tool:code-runner": "http://code-runner:9091",
    },
})

http.ListenAndServe(":8080", gw)
```

---

## Security model

### Threat mitigations

| Threat | Mitigation |
|---|---|
| **Stolen identity token** | The `AgentProofToken` is signed by the agent's private key. Without the private key, an attacker cannot generate a valid proof, even with a captured `AgentToken`. |
| **Proof token replay** | Every `AgentProofToken` carries a unique `jti`. The gateway's `ProofValidator` rejects any `jti` it has seen before. |
| **Token tampering** | All tokens are signed with ES256 (EC P-256). Any modification to header or payload invalidates the signature. |
| **Chain depth escalation** | The gateway validates that `chain_depth` values are strictly 0, 1, 2, … Any gap or reset causes validation to fail. |
| **Unauthorized tool access** | The gateway performs a subject × tool × action authorization check via the `Authorizer` interface on every request. |
| **Audience confusion** | The `AgentProofToken`'s `aud` claim is bound to the exact target URI. The gateway rejects any proof whose `aud` does not exactly match the request URI. |
| **Chain substitution** | The `chain_hash` claim in the proof token is `base64url(SHA-256(AT-1~AT-2~...~AT-N))`. Substituting a different chain invalidates the hash check. |

### What this PoC does not address

- **Token revocation** — tokens are valid until `exp`. Production systems need a revocation mechanism (e.g., short TTLs + JWKS refresh, or a revocation list).
- **IdP authentication** — in this PoC the IdP public key is configured statically. Production systems should fetch it dynamically from a JWKS endpoint with certificate pinning.
- **Persistent JTI store** — the replay store is in-memory per process. Restart clears it. A production gateway needs a distributed store (Redis, etc.) if it runs as multiple replicas.
- **mTLS transport** — adding mTLS between agents and the gateway for transport-layer identity is left for a future phase.

---

## Running tests

```bash
# All tests with race detector (same flags as CI)
make test

# Single package
go test ./pkg/identity/... -v -run TestAgentChain

# All quality gates (vet + test + govulncheck)
make check
```

The test suite covers 37 cases across four packages:

| Package | Tests | Coverage |
|---|---|---|
| `pkg/keys` | 5 | Key generation, JWK round-trip, coordinate padding, invalid curve point |
| `pkg/identity` | 17 | AgentToken happy/sad paths, chain sequential depth, proof aud/hash/replay/expiry |
| `internal/authz` | 7 | Allow/deny, action inheritance, wildcard subjects, missing fields |
| `internal/gateway` | 8 | Health, happy path, missing headers, tampered token, unauthorized subject, replay |

---

## Building

```bash
# Gateway binary
go build -o bin/gateway ./cmd/gateway

# WASM demo (requires wasm_exec.js from GOROOT)
make wasm

# Docker (multi-stage, distroless runtime image)
# docker build --build-arg BINARY=gateway -t agent-gateway .
```

---

## Configuration (gateway binary)

```
Usage of ./gateway:
  -port   string   listen port (default "8080")
  -issuer string   trusted IdP issuer ID (default "https://idp.example")
```

In production, IdP public keys should be fetched from a JWKS endpoint rather than generated ephemerally at startup.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Run `make hooks` once to install the pre-push quality gate.
3. `make check` must pass before opening a pull request. It runs the same four steps as CI: `go mod verify`, `go vet`, `go test -race`, `govulncheck`.
4. Keep each PR focused on a single concern. Tests are required for all new behaviour.

---

## OpenID Federation (Cross-Organisation Agents)

`pkg/federation` — implements **OpenID Federation 1.0** trust chains so the Agent Gateway can validate tokens from agents belonging to external organisations without any pre-shared key configuration.

### How it works

An agent from Org B presents its `agent+jwt` to Org A's gateway. The gateway:
1. Peeks at the `iss` claim — no static `AgentValidator` found for `idp.org-b.example`
2. Falls back to the `FederationResolver` in `Config.FederationResolver`
3. Resolver fetches (or reads from in-memory store) the Entity Configuration JWT for `idp.org-b.example`
4. Walks `authority_hints` → locates Trust Anchor → verifies Subordinate Statement with anchor key
5. Extracts Org B's IdP public key from the SS → verifies EC with that key
6. Constructs a one-shot `AgentValidator` with the resolved key → validates the agent token
7. Caches the resolved entity until `min(EC.exp, SS.exp)`

### Browser Demo — Federation tab

The interactive demo (`demo/index.html` → **OpenID Federation** tab) runs the complete three-step flow live in WASM:

| Step | WASM function | What it does |
|---|---|---|
| Build Federation Chain | `agentFabric.setupFederation()` | Generates Trust Anchor + Org B IdP keys, builds EC + SS, registers in InMemoryResolver |
| Issue Cross-Org Token | `agentFabric.issueOrgBAgentToken()` | Issues an `agent+jwt` using Org B's IdP key |
| Validate via Federation | `agentFabric.validateFederatedToken()` | Resolves Org B's key via trust chain, validates token — zero static config |

---

## Roadmap

- **Phase 2 — mTLS transport**: add X.509 URI SAN certs (SPIFFE) for transport-layer identity between agents and the gateway.
- **Phase 3 — Kubernetes deployment**: SPIRE-issued SVID workload certs, SPIFFE Workload API integration, Kubernetes RBAC bridge.
- **Phase 4 — Cross-domain trust**: token exchange service for multi-trust-domain agent pipelines (similar to the [WIMSE Identity Fabric](https://github.com/jralmaraz/wimse-identity-fabric) token exchange phase).
- **Phase 5 — Persistent authz**: replace `InMemoryAuthorizer` with a production-ready OpenFGA deployment with a schema and relation tuples defined as code.

---

## References

| Specification | Relevance |
|---|---|
| [draft-ietf-wimse-workload-creds](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/) | `cnf.jwk` structure, `alg: ES256` requirement |
| [draft-ietf-wimse-arch](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/) | Trust domain model, token exchange pattern |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key format |
| [RFC 7518 §6.2](https://www.rfc-editor.org/rfc/rfc7518#section-6.2) | EC key parameter encoding (32-byte left-pad) |
| [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) | Proof-of-possession key semantics (`cnf`) |
| [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) | Workload identity URI format (`spiffe://`) |
| [OpenFGA](https://openfga.dev/docs/concepts) | Zanzibar-style fine-grained authorization |
| [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) | Tool-server protocol the gateway is designed to front |
| [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | Entity Configurations, Subordinate Statements, trust chains for cross-org agent trust |
| [draft-ietf-oauth-rfc8725bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/) | JWT Best Current Practices — compliance audit applied 2026-08-02 across all validators |
| [draft-ietf-wimse-http-signature](https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/) | RFC 9421 HTTP Message Signatures as alternative to AgentProofToken — monitored |
| [draft-sweeney-wimse-credential-delegation](https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/) | Credential delegation protocol for AI agents — compared to CB4A in demo |
| [draft-reece-wimse-cross-org-delegation](https://datatracker.ietf.org/doc/draft-reece-wimse-cross-org-delegation/) | Cross-org delegation requirements — informs Identity Chaining scenario |
| [draft-sharma-oauth-identity-propagation-context](https://datatracker.ietf.org/doc/draft-sharma-oauth-identity-propagation-context/) | Multi-hop identity propagation context — future extension of Identity Chaining |

### Standards update process

Any new IETF draft discovered by the automated tracker requires completing the
[due-diligence checklist](docs/standards-tracking.md#due-diligence-checklist-for-every-standards-tracker-finding)
before the issue is closed. The checklist covers: triage, breaking-change diff review,
threat model verification (algorithm confusion, replay, audience escalation, key confusion),
demo updates, and test coverage.

---

## License

MIT — see [LICENSE](LICENSE).
