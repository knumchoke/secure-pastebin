// Package ui embeds the built single-page app (ui/dist). Run `npm run build`
// in ui/ before `go build`; the Dockerfile does this in its UI stage.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var Dist embed.FS

// FS returns the dist directory as the root.
func FS() (fs.FS, error) { return fs.Sub(Dist, "dist") }
