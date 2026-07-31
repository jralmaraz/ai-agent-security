# Security Model

This document describes the threat model for WIMSE Agent Fabric, the cryptographic mechanisms used, and the security boundaries of the proof-of-concept.

---

## Trust model

```
┌─────────────────────────────────────────────────┐
│                 Trust Domain                    │
│                                                 │
│   Identity Provider (IdP)                       │
│   ├── Signs AgentTokens (ES256, EC P-256)       │
│   └── Public key is the root of trust           │
│                                                 │
│   Agent Gateway                                 │
│   ├── Trusts: IdP public key(s)                 │
│   ├── Verifies: token sigs, chain depths        │
│   ├── Verifies: proof sig, aud, chain_hash, jti │
│   └── Enforces: authz policy                    │
│                                                 │
│   Agent Workloads                               │
│   ├── Each has an EC P-256 key pair             │
│   └── Public key bound in AgentToken (cnf.jwk)  │
└─────────────────────────────────────────────────┘
```

The IdP's EC P-256 public key is the single root of trust within a domain. Every agent that presents a token signed by that key is cryptographically identified by its SPIFFE URI (`sub`) and role (`role`).

---

## Threat analysis

### T1 — Stolen identity token

**Scenario:** An attacker intercepts `Agent-Identity-Token: <AT>` from network traffic.

**Why it fails:** The attacker does not have the agent's private key (corresponding to `cnf.jwk.x/y`). Without it, they cannot produce a valid `Agent-Proof-Token`. The gateway will reject any request that lacks a proof matching the identity token's bound public key.

**Controls:** `GenerateProof` requires `WorkloadKey *ecdsa.PrivateKey`. `ProofValidator.Validate` verifies the proof signature against the public key extracted from the identity token's `cnf.jwk`.

---

### T2 — Proof token replay

**Scenario:** An attacker captures a valid `Agent-Proof-Token: <APT>` and immediately re-submits it to gain a second, unauthorized access within the 5-minute window.

**Why it fails:** Every proof token carries a unique `jti` (128 random bits). `ProofValidator` records each `jti` in a mutex-protected map. The second submission finds the `jti` already present and returns an error.

**Controls:**

```go
// internal/gateway/server.go
if _, err := s.cfg.ProofValidator.Validate(identity.ProofValidateOptions{
    ...
    CheckReplay: true,  // JTI deduplication enforced
}); err != nil { ... }
```

**Limitation:** The JTI store is in-memory per process. Gateway restarts clear it. See [Known limitations](#known-limitations).

---

### T3 — Token tampering

**Scenario:** An attacker modifies the payload of a captured token — for example, changing `role` from `executor` to `orchestrator`, or changing `sub` to a higher-privileged identity.

**Why it fails:** The JWT is signed with ES256. The signature covers both the header and payload. Any byte change to either part produces a different hash, and the ECDSA signature will not verify against the IdP's public key.

**Controls:** `AgentValidator.Validate` uses `golang-jwt/jwt/v5` which performs signature verification before returning claims.

---

### T4 — Chain depth escalation

**Scenario:** A malicious executor generates an AgentToken with `chain_depth: 0` to masquerade as an orchestrator, or submits a chain with `chain_depth` values `[0, 2]` (skipping 1) to forge delegation history.

**Why it fails:** `AgentChain.Validate` enforces that `chain_depth` values must exactly equal their position in the chain slice (i.e., index 0 must have `chain_depth 0`, index 1 must have `chain_depth 1`, etc.). Any gap, reset, or skip causes validation to fail.

**Note:** The `chain_depth` value is part of the token payload which is covered by the IdP's signature. An executor cannot self-issue tokens; it must request them from the IdP. The IdP is responsible for issuing tokens with the correct `chain_depth` value.

---

### T5 — Unauthorized tool access

**Scenario:** A compromised executor agent attempts to call `tool:financial-db` when it has only been granted access to `tool:weather-api`.

**Why it fails:** The gateway performs an authorization check on every request:

```
subject: spiffe://cloud-a.example/executor
object:  tool:financial-db
action:  can_call
```

The `Authorizer` will return `Decision{Allowed: false}` unless an explicit rule permits this subject+object+action combination.

**Controls:** The `Authorizer` interface, `InMemoryAuthorizer`, and `OpenFGAAuthorizer` all default to deny. Rules must be explicitly added.

---

### T6 — Audience confusion

**Scenario:** An attacker captures a proof token generated for `tool:weather-api` and forwards it to `tool:code-runner`, hoping the gateway will accept it.

**Why it fails:** The `AgentProofToken`'s `aud` claim contains exactly one URI: the target the executor intended to call. The gateway extracts the actual request URI from `scheme + Host + URL.RequestURI()` and verifies it matches `aud` exactly.

---

### T7 — Chain substitution

**Scenario:** An attacker swaps the `Agent-Chain-Token` header with a different chain (one where they have more privileges), hoping the proof token will still be accepted.

**Why it fails:** The proof token contains `chain_hash = base64url(SHA-256(AT-1~AT-2~...~AT-N))`. The gateway computes the hash of the presented chain and compares it to `chain_hash`. A different chain produces a different hash.

---

### T8 — Token theft with mTLS enabled

**Scenario:** An attacker steals an `Agent-Identity-Token` (e.g., from a log or a compromised intermediate proxy) and attempts to replay it using their own TLS certificate.

**Why it fails:** When `MTLSClientCA` is set on the gateway, `verifyMTLSBinding` checks that the peer certificate's first URI SAN equals the `sub` claim of the identity token. The attacker's certificate has a different URI SAN (their own identity), so the check fails with 401.

**Controls:**

```go
// internal/gateway/server.go
func verifyMTLSBinding(r *http.Request, wantSub string) error {
    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
        return errors.New("no client certificate presented")
    }
    for _, u := range r.TLS.PeerCertificates[0].URIs {
        if u.String() == wantSub { return nil }
    }
    return fmt.Errorf("cert URI SANs %v do not match token subject %q", ...)
}
```

**Key design:** The agent uses the **same EC P-256 key pair** for its mTLS certificate, the `cnf.jwk` in the AgentToken, and the AgentProofToken signing key. Compromising the token alone is not enough — the attacker must also compromise the private key, defeating the binding check at both layers (mTLS cert and proof token).

**New in:** `pkg/keys/mtls.go` (`GenerateCA`, `IssueAgentCert`, `NewServerTLSConfig`, `NewClientTLSConfig`), `internal/gateway/server.go` (`Config.MTLSClientCA`, `verifyMTLSBinding`).

---

## Cryptographic primitives

| Primitive | Usage | Parameters |
|---|---|---|
| ECDSA | JWT signatures | P-256 curve (secp256r1), SHA-256 hash = ES256 |
| SHA-256 | Chain hash (`chain_hash`) | `crypto/sha256` stdlib |
| CSPRNG | JTI generation | `crypto/rand.Read`, 128 bits |
| Base64url | JWK coordinates, chain hash, JTI | `encoding/base64.RawURLEncoding` |

Key generation uses Go's `crypto/ecdsa.GenerateKey` with `elliptic.P256()` and `crypto/rand.Reader` (OS CSPRNG). Coordinate encoding left-pads to exactly 32 bytes per RFC 7518 §6.2.

---

## Known limitations

These are deliberate simplifications acceptable for a research PoC. Production systems must address them.

| Limitation | Impact | Production remedy |
|---|---|---|
| JTI replay store is in-memory | Restart clears it; multi-replica deployments share no state | Distributed cache (Redis/Memcached) with TTL aligned to proof token expiry |
| No token revocation | Tokens are valid until `exp` | Short TTLs (minutes) + JWKS endpoint polling + revocation list |
| IdP public key is static config | Key rotation requires restart | Fetch public key from JWKS endpoint; cache with short TTL |
| mTLS JTI store is in-memory per process | Gateway restart clears replay store | Distributed cache (Redis) with TTL aligned to proof token expiry |
| Single trust domain | No cross-domain agent calls | Add token exchange service (see Phase 4 roadmap) |
| No SPIRE integration | SPIFFE URIs are self-asserted | Integrate with SPIRE for workload attestation |

---

## Security contact

This is a research PoC. Please open a GitHub issue for security questions or design feedback.
