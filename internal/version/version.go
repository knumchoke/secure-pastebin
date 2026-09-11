// Package version holds build metadata injected via -ldflags.
package version

// Version is set at build time: -ldflags "-X github.com/knumchoke/secure-pastebin/internal/version.Version=v1.2.3".
var Version = "dev"
