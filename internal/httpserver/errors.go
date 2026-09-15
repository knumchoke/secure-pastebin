package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/challenge"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

type errorBody struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details,omitempty"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string, details map[string]any) {
	var b errorBody
	b.Error.Code, b.Error.Message, b.Error.Details = code, msg, details
	writeJSON(w, status, b)
}

// mapError translates domain errors to (status, code, details). Unknown errors
// become 500 internal; the caller logs the original.
func mapError(err error) (int, string, map[string]any) {
	var tooLarge *paste.ErrTooLarge
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, "paste_too_large", map[string]any{"limit_bytes": tooLarge.Limit, "actual_bytes": tooLarge.Actual}
	case errors.Is(err, paste.ErrNotFound), errors.Is(err, auth.ErrUserNotFound), errors.Is(err, challenge.ErrChallengeNotFound):
		return http.StatusNotFound, "not_found", nil
	case errors.Is(err, paste.ErrExpired):
		return http.StatusGone, "expired", nil
	case errors.Is(err, paste.ErrDeleted):
		return http.StatusGone, "deleted", nil
	case errors.Is(err, paste.ErrUnavailable):
		return http.StatusGone, "unavailable", nil
	case errors.Is(err, paste.ErrWrongPassword):
		return http.StatusUnauthorized, "wrong_password", nil
	case errors.Is(err, paste.ErrPasswordRequired):
		return http.StatusUnauthorized, "password_required", nil
	case errors.Is(err, auth.ErrBadCredentials):
		return http.StatusUnauthorized, "bad_credentials", nil
	case errors.Is(err, auth.ErrSessionNotFound):
		return http.StatusUnauthorized, "unauthenticated", nil
	case errors.Is(err, paste.ErrForbidden):
		return http.StatusForbidden, "forbidden", nil
	case errors.Is(err, auth.ErrNotAuthorised), errors.Is(err, auth.ErrOIDCStateInvalid):
		return http.StatusForbidden, "not_authorised", nil
	case errors.Is(err, paste.ErrChallengeRequired), errors.Is(err, challenge.ErrTokenInvalid):
		return http.StatusForbidden, "challenge_required", nil
	case errors.Is(err, challenge.ErrChallengeFailed):
		return http.StatusBadRequest, "challenge_failed", nil
	case errors.Is(err, paste.ErrInvalidUTF8):
		return http.StatusBadRequest, "invalid_utf8", nil
	case errors.Is(err, paste.ErrInvalidTTL):
		return http.StatusBadRequest, "invalid_ttl", nil
	case errors.Is(err, paste.ErrInvalidPassword):
		return http.StatusBadRequest, "invalid_password", nil
	case errors.Is(err, paste.ErrKDFBusy):
		return http.StatusServiceUnavailable, "kdf_busy", nil
	case errors.Is(err, paste.ErrKeyUnavailable):
		return http.StatusInternalServerError, "key_unavailable", nil
	default:
		return http.StatusInternalServerError, "internal", nil
	}
}

// fail writes err through mapError and logs 5xx with the request id.
func (h *handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, details := mapError(err)
	msg := err.Error()
	if status >= 500 {
		h.log.ErrorContext(r.Context(), "request failed", "code", code, "err", err, "path", r.URL.Path)
		if code == "internal" {
			msg = "internal error"
		}
	}
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "2")
	}
	writeError(w, status, code, msg, details)
}
