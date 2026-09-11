package paste

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"
)

// Canonicalize validates content and returns its canonical UTF-8 bytes.
func Canonicalize(content string, maxSize int64) ([]byte, error) {
	if !utf8.ValidString(content) {
		return nil, ErrInvalidUTF8
	}

	canonical := []byte(content)
	if !HasBOM(canonical) {
		withBOM := make([]byte, 0, len(BOM)+len(canonical))
		withBOM = append(withBOM, BOM...)
		canonical = append(withBOM, canonical...)
	}

	if int64(len(canonical)) > maxSize {
		return nil, &ErrTooLarge{Limit: maxSize, Actual: int64(len(canonical))}
	}
	return canonical, nil
}

// HashHex returns the lowercase hexadecimal SHA-256 digest of data.
func HashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// StripBOM removes one leading UTF-8 byte order mark when present.
func StripBOM(data []byte) []byte {
	if HasBOM(data) {
		return data[len(BOM):]
	}
	return data
}

// HasBOM reports whether data starts with the UTF-8 byte order mark.
func HasBOM(data []byte) bool {
	return bytes.HasPrefix(data, BOM)
}
