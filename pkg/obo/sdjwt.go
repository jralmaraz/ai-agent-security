package obo

// SD-JWT support for OBO delegation (draft-gco-oauth-delegate-sd-jwt-00)
//
// This file implements selective disclosure JWT (SD-JWT) for user identity tokens
// in the OBO flow. Instead of revealing all user claims to the OBO AS (and through
// it to the resource server), the agent selects only the disclosures the target
// resource actually needs.
//
// Example: a booking assistant requests OBO for the Calendar API.
//   - Plain JWT OBO:   AS sees email + given_name + phone_number + all user claims
//   - SD-JWT OBO:      Agent reveals only email; given_name stays private
//
// SD-JWT wire format (per draft-ietf-oauth-selective-disclosure-jwt):
//
//	<header.payload.signature>~<disc1>~<disc2>~
//
// Each disclosure is base64url(json([salt, claim_name, claim_value])).
// The JWT contains _sd: [sha256(disc1), sha256(disc2)] instead of the raw values.
//
// Status: draft-gco-oauth-delegate-sd-jwt-00 — individual draft, tracked, not yet
// WG-adopted. Implementation is illustrative of the privacy model, not production-ready.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const sdHashAlg = "sha-256"

// Disclosure is a single selectively-disclosable claim.
//
// Wire encoding: base64url(json([salt, claimName, claimValue]))
// Digest (embedded in JWT _sd array): base64url(SHA-256(wire))
type Disclosure struct {
	Name  string
	Value string
	salt  string
	wire  string // cached wire encoding
}

// newDisclosure creates a Disclosure with a cryptographically random 16-byte salt.
func newDisclosure(name, value string) (*Disclosure, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, fmt.Errorf("generate disclosure salt: %w", err)
	}
	d := &Disclosure{
		Name:  name,
		Value: value,
		salt:  base64.RawURLEncoding.EncodeToString(saltBytes),
	}
	arr, err := json.Marshal([]string{d.salt, name, value})
	if err != nil {
		return nil, fmt.Errorf("marshal disclosure: %w", err)
	}
	d.wire = base64.RawURLEncoding.EncodeToString(arr)
	return d, nil
}

// Wire returns the base64url-encoded disclosure string for inclusion in the SD-JWT
// wire format (the part after each ~ separator).
func (d *Disclosure) Wire() string { return d.wire }

// Digest returns the base64url-encoded SHA-256 hash of the wire encoding.
// This is what gets embedded in the JWT payload's _sd array.
func (d *Disclosure) Digest() string {
	h := sha256.Sum256([]byte(d.wire))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ── SD-JWT claims ─────────────────────────────────────────────────────────────

// SDUserClaims are the JWT payload claims of an SD-JWT user identity token.
// PII claims (email, given_name) are replaced by their digests in the _sd array;
// sub and scope are always-present (non-SD) claims.
type SDUserClaims struct {
	jwt.RegisteredClaims
	// Scope is always revealed — the OBO AS needs it for scope-subset enforcement.
	Scope string `json:"scope,omitempty"`
	// SD holds SHA-256 digests of the selectively-disclosable claim disclosures.
	SD []string `json:"_sd,omitempty"`
	// SDAlg identifies the hash algorithm used for _sd digests (always "sha-256").
	SDAlg string `json:"_sd_alg,omitempty"`
}

// ── SDUserToken ───────────────────────────────────────────────────────────────

// SDUserToken is an issued SD-JWT user token plus all its disclosures.
// The user (or agent holding the token on their behalf) decides which disclosures
// to include when presenting the token to the OBO AS.
type SDUserToken struct {
	// JWT is the signed base JWT (with _sd hashes, no raw PII values).
	JWT string
	// Disclosures are all the issued disclosures (one per SD claim).
	// The holder presents a subset of these to the verifier.
	Disclosures []*Disclosure
}

// Wire returns the full SD-JWT wire format including ALL disclosures:
//
//	<JWT>~<disc1>~<disc2>~
func (t *SDUserToken) Wire() string {
	return buildSDJWT(t.JWT, t.Disclosures)
}

// Present returns the SD-JWT wire format with only the named disclosures revealed.
// Unrevealed claims stay private — the verifier will not see them.
func (t *SDUserToken) Present(reveal []string) string {
	revealSet := make(map[string]bool, len(reveal))
	for _, n := range reveal {
		revealSet[n] = true
	}
	selected := make([]*Disclosure, 0, len(reveal))
	for _, d := range t.Disclosures {
		if revealSet[d.Name] {
			selected = append(selected, d)
		}
	}
	return buildSDJWT(t.JWT, selected)
}

func buildSDJWT(jwtStr string, disclosures []*Disclosure) string {
	parts := make([]string, 0, 1+len(disclosures)+1)
	parts = append(parts, jwtStr)
	for _, d := range disclosures {
		parts = append(parts, d.Wire())
	}
	parts = append(parts, "") // trailing ~ required by SD-JWT spec
	return strings.Join(parts, "~")
}

// ── SDUserIssuer ──────────────────────────────────────────────────────────────

// SDUserIssuer is an IdP that issues user tokens in SD-JWT format.
// PII claims (email, given_name) are selectively disclosable; sub and scope are
// always present so the OBO AS can perform scope-subset enforcement.
type SDUserIssuer struct {
	issuerID string
	key      *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewSDUserIssuer creates an SDUserIssuer.
func NewSDUserIssuer(issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) *SDUserIssuer {
	if ttl == 0 {
		ttl = defaultUserTTL
	}
	return &SDUserIssuer{issuerID: issuerID, key: key, ttl: ttl}
}

// Issue creates an SD-JWT user token.
//
// Always-revealed claims: sub, scope, iss, aud, iat, exp
// Selectively-disclosable (SD) claims: email, given_name
//
// The agent holding this token calls Present([]string{"email"}) to reveal only the
// email to the OBO AS, keeping given_name private.
func (u *SDUserIssuer) Issue(sub, email, givenName, scope, audience string) (*SDUserToken, error) {
	if sub == "" {
		return nil, errors.New("sub is required")
	}
	if audience == "" {
		return nil, errors.New("audience is required")
	}

	emailDisc, err := newDisclosure("email", email)
	if err != nil {
		return nil, fmt.Errorf("create email disclosure: %w", err)
	}
	nameDisc, err := newDisclosure("given_name", givenName)
	if err != nil {
		return nil, fmt.Errorf("create given_name disclosure: %w", err)
	}

	now := time.Now()
	claims := SDUserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    u.issuerID,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(u.ttl)),
		},
		Scope: scope,
		SD:    []string{emailDisc.Digest(), nameDisc.Digest()},
		SDAlg: sdHashAlg,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = SDUserTokenType
	signed, err := t.SignedString(u.key)
	if err != nil {
		return nil, fmt.Errorf("sign SD-JWT: %w", err)
	}

	return &SDUserToken{
		JWT:         signed,
		Disclosures: []*Disclosure{emailDisc, nameDisc},
	}, nil
}

// ── SDUserValidator ───────────────────────────────────────────────────────────

// SDUserValidateResult holds the verified claims from a presented SD-JWT user token.
type SDUserValidateResult struct {
	Claims      *SDUserClaims
	Subject     string
	Scope       string
	// RevealedClaims contains the name→value of every verified disclosure the
	// agent chose to reveal. Claims not in this map stayed private.
	RevealedClaims map[string]string
}

// SDUserValidator verifies SD-JWT user token presentations.
type SDUserValidator struct {
	issuerID string
	pubKey   *ecdsa.PublicKey
}

// NewSDUserValidator creates an SDUserValidator.
func NewSDUserValidator(issuerID string, pubKey *ecdsa.PublicKey) *SDUserValidator {
	return &SDUserValidator{issuerID: issuerID, pubKey: pubKey}
}

// Validate verifies an SD-JWT presentation wire string.
//
// Checks performed:
//   - Wire format: <JWT>~[disc1]~[disc2]~
//   - JWT signature (ES256) and standard claims (iss, aud, exp, iat, typ)
//   - Each presented disclosure: digest matches an entry in _sd
//   - Disclosure format: base64url(json([salt, name, value]))
func (v *SDUserValidator) Validate(presentation, audience string) (*SDUserValidateResult, error) {
	if presentation == "" {
		return nil, errors.New("presentation is required")
	}

	parts := strings.Split(presentation, "~")
	if len(parts) < 2 {
		return nil, errors.New("invalid SD-JWT: missing ~ separator (expected <JWT>~)")
	}

	jwtStr := parts[0]
	// Collect non-empty disclosure wire strings (last part is empty trailing ~)
	var discWires []string
	for _, p := range parts[1:] {
		if p != "" {
			discWires = append(discWires, p)
		}
	}

	// Verify JWT signature and standard claims.
	p := jwt.NewParser(
		jwt.WithIssuer(v.issuerID),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	)
	sdClaims := &SDUserClaims{}
	tok, err := p.ParseWithClaims(jwtStr, sdClaims, func(t *jwt.Token) (interface{}, error) {
		typ, _ := t.Header["typ"].(string)
		if typ != SDUserTokenType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, SDUserTokenType)
		}
		return v.pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify SD-JWT: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("SD-JWT invalid")
	}

	// Build a set of valid digests from the JWT _sd array.
	sdSet := make(map[string]bool, len(sdClaims.SD))
	for _, digest := range sdClaims.SD {
		sdSet[digest] = true
	}

	// Verify each presented disclosure and extract revealed claims.
	revealed := make(map[string]string)
	for _, wire := range discWires {
		// Compute digest and check it is in _sd.
		h := sha256.Sum256([]byte(wire))
		digest := base64.RawURLEncoding.EncodeToString(h[:])
		if !sdSet[digest] {
			return nil, fmt.Errorf("disclosure digest not found in token _sd (possible forgery)")
		}
		// Decode and parse [salt, name, value].
		raw, err := base64.RawURLEncoding.DecodeString(wire)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		var arr []string
		if err := json.Unmarshal(raw, &arr); err != nil || len(arr) != 3 {
			return nil, errors.New("invalid disclosure: expected JSON array [salt, name, value]")
		}
		name, value := arr[1], arr[2]
		revealed[name] = value
	}

	return &SDUserValidateResult{
		Claims:         sdClaims,
		Subject:        sdClaims.Subject,
		Scope:          sdClaims.Scope,
		RevealedClaims: revealed,
	}, nil
}
