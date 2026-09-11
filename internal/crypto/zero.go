// Package crypto holds the KDF gate, password hashing and (in WS2) the
// envelope encryption used for paste bodies.
package crypto

// Zero overwrites b with zeros. Best effort in a GC'd runtime (spec §6.2).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
