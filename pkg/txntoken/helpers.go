package txntoken

import (
	"crypto/sha256"
	"encoding/base64"
)

// Hash computes the base64url-encoded SHA-256 digest of a compact token string.
//
// Use this to compute the tth claim value when binding an AgentProofToken
// to a Transaction Token:
//
//	identity.ProofGenerateOptions{TxnToken: txnTokenString}  // tth set automatically
//
// The recipient re-computes Hash(txnToken) and compares it against the tth
// claim to verify the proof is bound to the correct transaction.
func Hash(tokenString string) string {
	h := sha256.Sum256([]byte(tokenString))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
