package txntoken

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultTTL = 5 * time.Minute

// Issuer signs Transaction Tokens on behalf of a Transaction Token Service (TTS).
type Issuer struct {
	issuerID string
	key      *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewIssuer creates a Txn-Token Issuer.
// ttl is the default token lifetime; zero or negative uses defaultTTL (5 min).
func NewIssuer(issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) *Issuer {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Issuer{issuerID: issuerID, key: key, ttl: ttl}
}

// IssueOptions controls Txn-Token issuance.
type IssueOptions struct {
	// Subject is the user identity (e.g. an OIDC sub claim) that initiated the transaction.
	Subject string
	// Audiences is the list of agents/services that will accept this token.
	Audiences []string
	// TxnID uniquely identifies the business transaction. Generated if empty.
	TxnID string
	// ReqCtx carries the entry-point request context (IP, requesting agent SPIFFE ID).
	ReqCtx *RequestContext
	// AzDetails carries authorization details granted by the Authorization Server.
	AzDetails []AuthorizationDetail
	// TTL overrides the issuer-level TTL. Zero uses the issuer default.
	// A negative value produces an already-expired token (for testing only).
	TTL time.Duration
}

// Issue creates and signs a Txn-Token JWT.
func (s *Issuer) Issue(opts IssueOptions) (string, error) {
	if opts.Subject == "" {
		return "", errors.New("subject is required")
	}
	if len(opts.Audiences) == 0 {
		return "", errors.New("at least one audience is required")
	}

	txnID := opts.TxnID
	if txnID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generate txn ID: %w", err)
		}
		txnID = hex.EncodeToString(b)
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = s.ttl
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuerID,
			Subject:   opts.Subject,
			Audience:  jwt.ClaimStrings(opts.Audiences),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Txn:       txnID,
		ReqCtx:    opts.ReqCtx,
		AzDetails: opts.AzDetails,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = TokenType
	return t.SignedString(s.key)
}
