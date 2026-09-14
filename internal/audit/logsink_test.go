package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLogSink_EmitsStructuredEvent(t *testing.T) {
	var buf bytes.Buffer
	sink := NewLogSink(slog.New(slog.NewJSONHandler(&buf, nil)))
	actorID, pasteID := uuid.New(), uuid.New()
	at := time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC)
	sink.Record(WithRequestInfo(context.Background(), "10.0.0.5", "curl/8"), Event{
		At: at, Event: PasteCreated, ActorID: &actorID, PasteID: &pasteID,
		Outcome: OutcomeSuccess, Details: map[string]any{"size_bytes": 12},
	})
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	for key, want := range map[string]any{
		"level": "INFO", "msg": "audit", "event": PasteCreated,
		"outcome": OutcomeSuccess, "at": at.Format(time.RFC3339),
		"ip": "10.0.0.5", "user_agent": "curl/8",
		"actor_id": actorID.String(), "paste_id": pasteID.String(),
	} {
		if got[key] != want {
			t.Errorf("%s = %v, want %v", key, got[key], want)
		}
	}
	details, ok := got["details"].(map[string]any)
	if !ok || details["size_bytes"] != float64(12) {
		t.Errorf("details = %#v", got["details"])
	}
}

func TestLogSink_RequestInfoFillsEachEmptyField(t *testing.T) {
	for _, tc := range []struct {
		name, ip, ua, wantIP, wantUA string
	}{
		{"both empty", "", "", "10.0.0.5", "curl/8"},
		{"explicit IP", "192.0.2.1", "", "192.0.2.1", "curl/8"},
		{"explicit user agent", "", "app/1", "10.0.0.5", "app/1"},
		{"both explicit", "192.0.2.1", "app/1", "192.0.2.1", "app/1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			sink := NewLogSink(slog.New(slog.NewJSONHandler(&buf, nil)))
			sink.Record(WithRequestInfo(context.Background(), "10.0.0.5", "curl/8"), Event{
				Event: LoginFailure, Outcome: OutcomeFailure, IP: tc.ip, UserAgent: tc.ua,
			})
			var got map[string]any
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["ip"] != tc.wantIP || got["user_agent"] != tc.wantUA {
				t.Errorf("ip/ua = %v/%v, want %s/%s", got["ip"], got["user_agent"], tc.wantIP, tc.wantUA)
			}
			if _, ok := got["details"]; ok {
				t.Error("empty details should be omitted")
			}
		})
	}
}
