package ui

import (
	"io/fs"
	"testing"
)

func TestFS_Exists(t *testing.T) {
	f, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(f, ".keep"); err != nil {
		t.Fatalf("dist/.keep must be embedded: %v", err)
	}
}
