package httpserver

import (
	"crypto/rand"
	"encoding/base64"
)

// randomToken returns nBytes of CSPRNG output, base64url without padding.
// Local copy so httpserver does not depend on internal/auth helpers.
func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
