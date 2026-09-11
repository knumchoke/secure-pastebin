package cli

import (
	"bytes"
	"testing"
)

func TestRun_NoArgsPrintsUsageAndExits2(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run(nil, func(string) string { return "" }, nil, &out, &errb)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !bytes.Contains(errb.Bytes(), []byte("usage: pastebin")) {
		t.Fatalf("stderr = %q, want usage", errb.String())
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"bogus"}, func(string) string { return "" }, nil, &out, &errb)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_Version(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"version"}, func(string) string { return "" }, nil, &out, &errb)
	if code != 0 || !bytes.Contains(out.Bytes(), []byte("pastebin ")) {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
}
