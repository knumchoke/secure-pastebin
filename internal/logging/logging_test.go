package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestNew_JSONAndLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "warn")
	log.Info("hidden")
	log.Warn("shown", "k", "v")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %s", buf.String())
	}
	if rec["msg"] != "shown" || rec["k"] != "v" || rec["level"] != "WARN" {
		t.Errorf("got %v", rec)
	}
}

func TestRequestID(t *testing.T) {
	ctx := WithRequestID(context.Background(), "abc")
	if RequestID(ctx) != "abc" || RequestID(context.Background()) != "" {
		t.Fatal("request id round trip failed")
	}
}
