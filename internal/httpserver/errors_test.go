package httpserver

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/challenge"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

func TestMapError(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{paste.ErrNotFound, 404, "not_found"},
		{paste.ErrExpired, 410, "expired"},
		{paste.ErrDeleted, 410, "deleted"},
		{paste.ErrUnavailable, 410, "unavailable"},
		{paste.ErrWrongPassword, 401, "wrong_password"},
		{paste.ErrPasswordRequired, 401, "password_required"},
		{auth.ErrBadCredentials, 401, "bad_credentials"},
		{auth.ErrSessionNotFound, 401, "unauthenticated"},
		{paste.ErrForbidden, 403, "forbidden"},
		{auth.ErrNotAuthorised, 403, "not_authorised"},
		{challenge.ErrTokenInvalid, 403, "challenge_required"},
		{challenge.ErrChallengeFailed, 400, "challenge_failed"},
		{challenge.ErrChallengeNotFound, 404, "not_found"},
		{paste.ErrInvalidUTF8, 400, "invalid_utf8"},
		{paste.ErrInvalidTTL, 400, "invalid_ttl"},
		{paste.ErrInvalidPassword, 400, "invalid_password"},
		{&paste.ErrTooLarge{Limit: 10, Actual: 11}, 413, "paste_too_large"},
		{paste.ErrKDFBusy, 503, "kdf_busy"},
		{paste.ErrKeyUnavailable, 500, "key_unavailable"},
		{errors.New("boom"), 500, "internal"},
	}
	for _, c := range cases {
		st, code, _ := mapError(c.err)
		if st != c.status || code != c.code {
			t.Errorf("%v → %d %s, want %d %s", c.err, st, code, c.status, c.code)
		}
	}
	_, _, d := mapError(&paste.ErrTooLarge{Limit: 10, Actual: 11})
	if d["limit_bytes"] != int64(10) || d["actual_bytes"] != int64(11) {
		t.Errorf("details = %v", d)
	}
}

func TestWriteError_Envelope(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, 413, "paste_too_large", "too big", map[string]any{"limit_bytes": 1})
	if rr.Code != 413 || rr.Header().Get("Content-Type") != "application/json; charset=utf-8" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", rr.Header())
	}
	var body struct {
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Error.Code != "paste_too_large" || body.Error.Details["limit_bytes"] != float64(1) {
		t.Fatalf("body = %s", rr.Body.String())
	}
}
