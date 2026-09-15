package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

func userJSON(u auth.User) map[string]any {
	return map[string]any{"id": u.ID.String(), "username": u.Username, "display_name": u.DisplayName,
		"is_admin": u.IsAdmin, "provider": string(u.Provider)}
}

// decodeJSON reads a small JSON body strictly (unknown fields rejected).
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// limit runs a rate-limit check; on denial it writes 429 and returns false.
func (h *handlers) limit(w http.ResponseWriter, r *http.Request, scope ratelimit.Scope, key string) bool {
	d := h.limiter.Allow(r.Context(), scope, key)
	if d.Allowed {
		return true
	}
	secs := int(d.RetryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	h.metrics.Inc(MetricRateLimited)
	var actor *uuid.UUID
	if p := principalFrom(r.Context()); p != nil {
		actor = &p.UserID
	}
	h.audit.Record(r.Context(), audit.Event{At: h.now(), Event: audit.RateLimited, ActorID: actor, Outcome: audit.OutcomeDenied,
		Details: map[string]any{"scope": string(scope)}})
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests", map[string]any{"retry_after_seconds": secs})
	return false
}

// startSession replaces any presented session with a fresh one (fixation defence).
func (h *handlers) startSession(w http.ResponseWriter, r *http.Request, u auth.User) (auth.Session, error) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = h.sessions.Delete(r.Context(), c.Value)
	}
	sess, err := h.sessions.Create(r.Context(), u.ID, h.cfg.SessionIdleTTL, h.cfg.SessionAbsoluteTTL)
	if err != nil {
		return auth.Session{}, err
	}
	h.setSessionCookie(w, sess)
	return sess, nil
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if h.local == nil || !h.cfg.LocalEnabled() {
		writeError(w, http.StatusNotFound, "not_found", "local login disabled", nil)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil || in.Username == "" || in.Password == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "username and password required", nil)
		return
	}
	if !h.limit(w, r, ratelimit.ScopeLoginIP, ipFrom(r.Context())) || !h.limit(w, r, ratelimit.ScopeLogin, in.Username) {
		return
	}
	u, err := h.local.Authenticate(r.Context(), in.Username, in.Password)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	sess, err := h.startSession(w, r, u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(u), "csrf_token": sess.CSRFToken})
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	si, _ := sessionFrom(r.Context())
	_ = h.sessions.Delete(r.Context(), si.Session.ID)
	h.clearSessionCookie(w)
	h.audit.Record(r.Context(), audit.Event{At: h.now(), Event: audit.Logout, ActorID: &si.User.ID, Outcome: audit.OutcomeSuccess})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	si, _ := sessionFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(si.User), "csrf_token": si.Session.CSRFToken})
}

func (h *handlers) oidcStart(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		writeError(w, http.StatusNotFound, "not_found", "oidc disabled", nil)
		return
	}
	url, err := h.oidc.Start(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *handlers) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		writeError(w, http.StatusNotFound, "not_found", "oidc disabled", nil)
		return
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "state and code required", nil)
		return
	}
	u, err := h.oidc.Complete(r.Context(), state, code)
	if err != nil {
		if errors.Is(err, auth.ErrNotAuthorised) || errors.Is(err, auth.ErrOIDCStateInvalid) {
			h.fail(w, r, err)
			return
		}
		h.log.WarnContext(r.Context(), "oidc callback failed", "err", err)
		writeError(w, http.StatusBadRequest, "oidc_failed", "login failed", nil)
		return
	}
	if _, err := h.startSession(w, r, u); err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/new", http.StatusFound)
}
