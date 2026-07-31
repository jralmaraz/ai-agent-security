# Token Format Reference

This document specifies the exact JWT structure for each token type in WIMSE Agent Fabric.

---

## AgentToken (`agent+jwt`)

An AgentToken identifies one agent workload at one hop of a delegation chain. It is issued by a trusted Identity Provider and signed with the IdP's EC P-256 key.

### JOSE Header

```jsonc
{
  "typ": "agent+jwt",    // required — distinguishes from other JWT types
  "alg": "ES256",        // required — EC P-256 with SHA-256
  "kid": "idp-key-2026"  // optional — key ID for JWKS lookup
}
```

### Payload

```jsonc
{
  // Standard JWT claims (RFC 7519)
  "iss": "https://idp.agent-fabric.example",   // IdP issuer — absolute URI
  "sub": "spiffe://cloud-a.example/agent/orch", // agent SPIFFE URI
  "aud": ["https://gateway.example"],           // intended recipients
  "jti": "aB3zR7mNqP...",                       // unique token ID (128 random bits, base64url)
  "iat": 1753995600,                             // issued-at (NumericDate)
  "nbf": 1753995600,                             // not-before (same as iat)
  "exp": 1753999200,                             // expiry (iat + TTL)

  // Agent-fabric-specific claims
  "role": "orchestrator",  // "orchestrator" | "executor" | "tool-server"
  "chain_depth": 0,         // 0-indexed hop position; 0 = originating orchestrator

  // Proof-of-possession key (RFC 7800 §3.2)
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<base64url, 32 bytes left-padded>",
      "y": "<base64url, 32 bytes left-padded>",
      "alg": "ES256",
      "kid": "wl-key-2026"   // optional
    }
  }
}
```

### Validation steps

1. Verify ES256 signature against the IdP's public key.
2. Check `typ == "agent+jwt"`.
3. Verify `exp`, `nbf`, `iat` are present and valid.
4. Verify `iss` matches the expected issuer ID.
5. Deserialize `cnf.jwk` and verify the point is on the P-256 curve (`IsOnCurve`).

---

## AgentChain (wire format)

The delegation chain is transmitted in HTTP headers as a `~`-separated string of compact AgentToken JWTs:

```
Agent-Chain-Token: AT-1~AT-2~...~AT-N
```

where:
- `AT-1` has `chain_depth: 0` (the originating orchestrator)
- `AT-2` has `chain_depth: 1`
- `AT-N` has `chain_depth: N-1`

The chain hash used in proof tokens is:

```
chain_hash = base64url(SHA-256(AT-1~AT-2~...~AT-N))
```

The SHA-256 is taken over the UTF-8 bytes of the full `~`-joined wire string.

### Chain validation rules

| Rule | Enforced by |
|---|---|
| Each token individually valid (sig, exp, typ, iss) | `AgentValidator.Validate` |
| `chain_depth[i] == i` for all i | `AgentChain.Validate` |
| No gaps or resets in depth | `AgentChain.Validate` |
| Each token's issuer must have a registered validator | `AgentChain.Validate` |

---

## AgentProofToken (`application/agent-proof+jwt`)

A per-request proof-of-possession token signed by the calling agent's own private key (the key bound via `cnf.jwk` in its AgentToken). Generated fresh for every request.

### JOSE Header

```jsonc
{
  "typ": "application/agent-proof+jwt",  // required
  "alg": "ES256"                          // required
}
```

### Payload

```jsonc
{
  "aud": ["https://tool-server.example/api/weather"],  // exact target URI
  "jti": "cX8pQ2nWsK...",                               // unique ID (for replay detection)
  "iat": 1753995600,
  "nbf": 1753995600,
  "exp": 1753995900,                                    // default: iat + 5 minutes

  // Chain binding
  "chain_hash": "base64url(SHA-256(AT-1~AT-2~...~AT-N))"
}
```

### Validation steps

1. Verify ES256 signature against the public key from `cnf.jwk` in the caller's AgentToken.
2. Check `typ == "application/agent-proof+jwt"`.
3. Verify `exp`, `nbf`, `iat`.
4. Verify `aud` contains exactly the request URI (exact string match).
5. Verify `chain_hash == SHA-256(presented chain wire string)`.
6. If replay detection is enabled, verify `jti` has not been seen before; record it.

---

## HTTP headers summary

| Header | Content | Required |
|---|---|---|
| `Agent-Identity-Token` | Compact AgentToken JWT for the current hop | Yes |
| `Agent-Chain-Token` | Full chain wire string `AT-1~AT-2~...~AT-N` | Yes |
| `Agent-Proof-Token` | Compact AgentProofToken JWT | Yes |

All three headers must be present. If any is missing the gateway returns `401 Unauthorized`.

---

## Worked example

**Setup:**
- IdP key pair: `(idpPriv, idpPub)`
- Orchestrator key pair: `(orchPriv, orchPub)`
- Executor key pair: `(execPriv, execPub)`

**Step 1 — Issue orchestrator token:**

```go
issuer := identity.NewAgentIssuer("https://idp.example", idpPriv, time.Hour)
orchTok, _ := issuer.Issue(identity.IssueOptions{
    Subject:     "spiffe://cloud-a.example/orch",
    Role:        identity.RoleOrchestrator,
    ChainDepth:  0,
    WorkloadKey: orchPub,
})
chain := identity.AgentChain{orchTok}
```

**Step 2 — Orchestrator delegates to executor:**

```go
execTok, _ := issuer.Issue(identity.IssueOptions{
    Subject:     "spiffe://cloud-a.example/exec",
    Role:        identity.RoleExecutor,
    ChainDepth:  1,
    WorkloadKey: execPub,
})
chain, _ = chain.Extend(execTok)
// chain.String() == "orchTok~execTok"
```

**Step 3 — Executor generates a proof for a tool call:**

```go
proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
    TargetURI:   "https://tool-server.example/api/weather",
    Chain:       chain,
    WorkloadKey: execPriv,
})
```

**Step 4 — Executor makes the HTTP request:**

```http
GET /api/weather HTTP/1.1
Host: tool-server.example
Agent-Identity-Token: <execTok>
Agent-Chain-Token: <orchTok>~<execTok>
Agent-Proof-Token: <proof>
```

**Step 5 — Gateway validates and forwards:**

1. Parse `Agent-Identity-Token` → extract `execPub` from `cnf.jwk`
2. Parse `Agent-Chain-Token` → validate `orchTok` (depth 0) + `execTok` (depth 1)
3. Parse `Agent-Proof-Token` → verify sig with `execPub`, `aud`, `chain_hash`, `jti`
4. Authorize: `spiffe://cloud-a.example/exec` × `tool:weather` × `can_call` → allowed
5. Forward to upstream tool server
