# Standards Tracking Policy

This document explains how the WIMSE Agent Fabric PoC tracks the IETF and OpenID
standards it implements, and records the decisions made about which standards to follow.

## Tracking Mechanisms

### 1. IETF Datatracker API (primary — revision detection)

`scripts/check_standards.py` polls `https://datatracker.ietf.org/api/v1/doc/document/<id>/`
daily via GitHub Actions. When `rev` in the API response differs from `last_known_rev` in
`standards-baseline.json`, a labelled GitHub issue is opened automatically.

### 2. RSS/Atom Feeds (supplement — for non-Datatracker publications)

Standards without a Datatracker entry (e.g. OpenID Federation 1.0, which is published by
OIDF rather than IETF) are tracked via the OpenID Foundation RSS feed
(`https://openid.net/feed/`). The checker matches items by keyword and records the
latest GUID so reruns don't re-alert.

### 3. WG-level Atom Feeds (discovery — unknown drafts)

The checker also polls the IETF WG-level Atom feeds:
- WIMSE WG: `https://datatracker.ietf.org/group/wimse/documents/feed/`
- OAuth WG: `https://datatracker.ietf.org/group/oauth/documents/feed/`

Any draft ID found in the feed that is **not already in `standards-baseline.json`** is
reported as a "new draft discovered" in the GitHub issue. This prevents missing a
newly-chartered draft that is immediately relevant.

### 4. GitHub Repository Watching (precision supplement — human-driven)

Each tracked standard has a `source_repo` field in `standards-baseline.json` pointing
to the editors' GitHub repository. The Datatracker only reflects formally submitted
revisions; the GitHub repo contains in-progress editor copies and active design
discussions.

**Decision**: Watch these repos for **Issues and Pull Requests only** — not all commits.
Commit-level watching produces excessive noise (editor toolchain changes, formatting
fixes, CI tweaks). Issues and PRs expose breaking design changes before they appear in
a new `-xx` revision, giving early warning for any structural impact on this PoC.

| WG / Publisher | GitHub Organization / Repo |
|---|---|
| IETF WIMSE WG (WIT, WPT, mTLS, HTTP-sig) | `github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` |
| IETF WIMSE WG (Architecture) | `github.com/ietf-wg-wimse/draft-ietf-wimse-arch` |
| IETF WIMSE WG (Identifiers) | `github.com/ietf-wg-wimse/draft-ietf-wimse-identifier` |
| IETF OAuth WG (Transaction Tokens) | `github.com/oauth-wg/oauth-transaction-tokens` |
| IETF OAuth WG (Identity Chaining) | `github.com/oauth-wg/oauth-identity-chaining` |
| IETF OAuth WG (SPIFFE Client Auth) | `github.com/oauth-wg/oauth-spiffe-client-authentication` |
| IETF OAuth WG (SD-JWT base) | `github.com/oauth-wg/oauth-selective-disclosure-jwt` |
| OpenID Foundation | Issues: `github.com/openid/federation` |
| CB4A (Credential Broker for Agents) | Individual draft — no WG repo yet |

---

## Standard Inclusion Decisions

### Included

| Standard | Why included |
|---|---|
| WIT / AgentToken | Core agent identity credential — delegates from WIT structure |
| WPT / AgentProofToken | Per-request proof of possession — binds each hop in delegation chain |
| Identifiers | Governs SPIFFE URI format used in every sub claim |
| mTLS binding | Transport-layer agent authentication — cert/token binding |
| WIMSE Architecture | Defines token exchange model and trust domain semantics |
| CB4A | Credential broker for AI agents — PDP/CDP/Tier model |
| DPoP (RFC 9449) | Proof-of-possession for CB4A minted tokens |
| OpenID Federation 1.0 | Cross-org trust chain resolution |
| Txn-Token | User context through multi-agent chains; AgentProofToken tth binding |
| SPIFFE Client Auth | AgentToken authenticates directly to OAuth AS — no shared secrets |
| Identity Chaining | RFC 8693 cross-domain exchange with JWT authorization grant |

### Excluded — SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`)

**Decision**: Do not add SD-JWT VC to the tracked baseline.

**Rationale**: SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`, currently at rev-17) adds a
**Verifiable Credential** layer (vct claim, status lists, Issuer-Holder-Verifier ceremony)
on top of the base SD-JWT format. This model is designed for **human credentials**
(national IDs, diplomas, employee badges) where a human holder selectively presents
claims to a human-facing verifier.

For AI agent identity, the core security requirement is authenticated delegation
(who authorized this agent to act) and proof-of-possession (this request was signed
by the legitimate agent). Both are handled by AgentToken + AgentProofToken + AgentChain.
The VC layer adds no value for machine-to-machine trust establishment between agents.

**Revisit trigger**: If agent-to-human interactions become a target use case (e.g. an
AI agent presenting a verifiable credential to a human-facing service on behalf of a
user), SD-JWT VC becomes relevant at that boundary.

---

## Baseline File

`standards-baseline.json` at the repository root is the single source of truth. Fields:
- `last_known_rev` / `implemented_rev`: track spec version vs implementation version
- `source_repo`: GitHub URL for issues/PR watching (see above)
- `wg_feeds`: WG-level Atom feeds for new draft discovery
- `rss_url` / `rss_keywords` / `last_rss_guid`: RSS tracking for OIDF publications

The GitHub Actions workflow `.github/workflows/standards-tracker.yml` runs daily,
calls `scripts/check_standards.py`, and opens a labelled issue on any change.
