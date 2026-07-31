# Agent Gateway

The Agent Gateway is an MCP-compatible HTTP reverse proxy that sits between AI agent workloads and tool servers. It validates agent identity chains, enforces authorization policy, and detects proof token replays before forwarding any request.

---

## Request lifecycle

```
Agent Workload
     │
     │  HTTP request with three headers:
     │    Agent-Identity-Token: <AT-N>         ← leaf token for this hop
     │    Agent-Chain-Token: AT-1~AT-2~...~AT-N ← full delegation chain
     │    Agent-Proof-Token: <APT>              ← per-request proof
     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Agent Gateway                          │
│                                                             │
│  Step 1: Parse Agent-Identity-Token                         │
│    • Decode JWT header/payload                              │
│    • Verify ES256 signature with any trusted IdP public key │
│    • Verify exp, nbf, iat, typ=agent+jwt, iss               │
│    • Extract WorkloadKey from cnf.jwk                       │
│         → 401 if any check fails                            │
│                                                             │
│  Step 2: Parse and validate Agent-Chain-Token               │
│    • Split on '~' → [AT-1, AT-2, ..., AT-N]                │
│    • For each AT-i: verify signature, exp, typ, iss         │
│    • Verify chain_depth[i] == i (sequential, no gaps)       │
│         → 401 if any check fails                            │
│                                                             │
│  Step 3: Parse and validate Agent-Proof-Token               │
│    • Verify ES256 signature with WorkloadKey from step 1    │
│    • Verify exp, nbf, iat, typ=application/agent-proof+jwt  │
│    • Verify aud == scheme://Host/path?query                  │
│    • Verify chain_hash == SHA-256(chain wire string)        │
│    • Record jti → reject if already seen                    │
│         → 401 if any check fails                            │
│                                                             │
│  Step 4: Authorization check                                │
│    • subject = AT-N.sub                                     │
│    • object  = configured tool name (e.g. "tool:echo")      │
│    • action  = can_call                                      │
│    • Call Authorizer.Authorize(ctx, Request{...})           │
│         → 403 if denied                                     │
│                                                             │
│  Step 5: Forward to upstream tool server                    │
│    • Reverse-proxy the original request                     │
│    • wimse.agent and wimse.chain injected into Gin context  │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
Tool Server (weather API, database, code runner, …)
```

---

## Configuration

```go
gw := gateway.New(gateway.Config{
    // Validators: one entry per trusted IdP.
    // The gateway tries each validator until one succeeds.
    Validators: map[string]*identity.AgentValidator{
        "https://idp-a.example": validatorA,
        "https://idp-b.example": validatorB,
    },

    // ProofValidator: shared across all routes for this gateway instance.
    // Owns the JTI replay store — do not share across processes.
    ProofValidator: identity.NewProofValidator(),

    // Authz: authorization backend.
    Authz: authz.NewInMemoryAuthorizer(), // or OpenFGAAuthorizer

    // Routes: tool name → upstream base URL.
    // Each entry creates a protected route group at /tools/<tool-path>/.
    Routes: map[string]string{
        "tool:weather-api": "http://weather:9090",
        "tool:code-runner": "http://runner:9091",
        "tool:vector-db":   "http://qdrant:6333",
    },
})

http.ListenAndServe(":8080", gw)
```

### Route registration

For each entry in `Routes`, the gateway registers a route group at `/tools/<tool-path>/`. The tool path is derived from the tool name by stripping the `tool:` prefix:

| Tool name | Route prefix |
|---|---|
| `tool:weather-api` | `/tools/weather-api/*` |
| `tool:code-runner` | `/tools/code-runner/*` |

All HTTP methods are supported (GET, POST, PUT, DELETE, …). The reverse proxy forwards the full path to the upstream.

### Built-in endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{"status":"ok"}` — no auth required |

---

## Multi-IdP support

The gateway supports tokens from multiple IdPs simultaneously. Supply one `AgentValidator` per trusted issuer in the `Validators` map, keyed by issuer ID (must match the `iss` claim in tokens):

```go
Validators: map[string]*identity.AgentValidator{
    "https://idp.cloud-a.example": identity.NewAgentValidator(
        "https://idp.cloud-a.example", cloudAPublicKey,
    ),
    "https://idp.cloud-b.example": identity.NewAgentValidator(
        "https://idp.cloud-b.example", cloudBPublicKey,
    ),
},
```

The gateway tries all validators; the first successful validation wins. Chain validation uses the same validators map, which means a single chain can mix tokens from different IdPs (e.g., for cross-domain delegation flows).

---

## Authorization backends

### InMemoryAuthorizer (development / testing)

```go
a := authz.NewInMemoryAuthorizer()

// Grant a specific agent access to a tool
a.Allow("spiffe://cloud-a.example/orch", "tool:weather-api", authz.ActionCall)

// Grant write access to a database (implies read access too)
a.Allow("spiffe://cloud-a.example/exec", "tool:vector-db", authz.ActionWrite)

// Grant all agents read access to public tools
a.Allow("*", "tool:public-info", authz.ActionRead)
```

Action inheritance:
- `can_call` → satisfies `can_call` and `can_read`
- `can_write` → satisfies `can_write` and `can_read`
- `can_read` → satisfies only `can_read`

### OpenFGAAuthorizer (production)

```go
a, err := authz.NewOpenFGAAuthorizer(authz.OpenFGAConfig{
    APIURL:               "http://openfga-server:8080",
    StoreID:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    AuthorizationModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", // optional
})
```

The OpenFGA authorizer maps WIMSE subjects to OpenFGA users by escaping the SPIFFE URI:

```
spiffe://cloud-a.example/orch  →  agent:spiffe__cloud-a-example_orch
```

Relations in the OpenFGA model should be named `can_call`, `can_read`, `can_write` to match the `Action` constants.

---

## Reading agent identity in a tool handler

If your tool server is also a Gin application, you can use the `AgentAuth` middleware directly instead of the full gateway proxy. The middleware injects the validated identity into the Gin context:

```go
import (
    "github.com/jralmaraz/wimse-agent-fabric/internal/authz"
    "github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
)

r.GET("/api/weather", authz.AgentAuth(validator, validators, pv, authz, "tool:weather-api", authz.ActionCall), func(c *gin.Context) {
    // Retrieve the validated agent (always present after successful middleware)
    va := c.MustGet(authz.ContextKeyAgent).(*identity.ValidatedAgent)
    chain := c.MustGet(authz.ContextKeyChain).(identity.AgentChain)

    log.Printf("caller: %s (role=%s, depth=%d, chain=%d hops)",
        va.Claims.Subject, va.Claims.Role, va.Claims.ChainDepth, chain.Len())

    c.JSON(200, gin.H{"weather": "sunny"})
})
```

---

## Request URI construction

The gateway constructs the canonical request URI for proof token `aud` validation as:

```
scheme + "://" + c.Request.Host + c.Request.URL.RequestURI()
```

where `scheme` is `"https"` if `c.Request.TLS != nil`, otherwise `"http"`.

The agent generating the proof must use the same URI. In production (TLS), this will always be an `https://` URI. Match it exactly — the `aud` check is a string equality comparison.

---

## Error responses

All errors are returned as JSON:

```jsonc
// 401 Unauthorized
{ "error": "missing Agent-Identity-Token" }
{ "error": "invalid agent identity token: parse agent token: token is expired" }
{ "error": "chain validation failed: chain[1]: expected chain_depth 1, got 2" }
{ "error": "invalid agent proof token: replay detected: jti \"aB3z...\" already used" }

// 403 Forbidden
{ "error": "access denied", "reason": "no rule permits spiffe://x/y → can_call on tool:db" }

// 500 Internal Server Error
{ "error": "authz error: OpenFGA check: connection refused" }
```
