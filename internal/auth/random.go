package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomToken returns nBytes of CSPRNG output, base64url-encoded without padding.
func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
