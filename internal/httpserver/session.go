package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

const sessionCookie = "pb_sess"

type sessionInfo struct {
	Session auth.Session
	User    auth.User
}

type sessionKey struct{}

func sessionFrom(ctx context.Context) (sessionInfo, bool) {
	si, ok := ctx.Value(sessionKey{}).(sessionInfo)
	return si, ok
}

func principalFrom(ctx context.Context) *paste.Principal {
	si, ok := sessionFrom(ctx)
	if !ok {
		return nil
	}
	p := si.User.Principal()
	return &p
}

// loadSession resolves the cookie to a session+user. Any failure = anonymous.
func (h *handlers) loadSession() middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(sessionCookie)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			sess, err := h.sessions.Get(r.Context(), c.Value)
			if err != nil {
				if !errors.Is(err, auth.ErrSessionNotFound) {
					h.log.WarnContext(r.Context(), "session lookup failed", "err", err)
				}
				next.ServeHTTP(w, r)
				return
			}
			u, err := h.users.GetByID(r.Context(), sess.UserID)
			if err != nil || u.Disabled {
				_ = h.sessions.Delete(r.Context(), sess.ID)
				next.ServeHTTP(w, r)
				return
			}
			_ = h.sessions.Touch(r.Context(), sess.ID, h.cfg.SessionIdleTTL)
			ctx := context.WithValue(r.Context(), sessionKey{}, sessionInfo{Session: sess, User: u})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (h *handlers) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := sessionFrom(r.Context()); !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required", nil)
			return
		}
		next(w, r)
	}
}

func (h *handlers) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		si, _ := sessionFrom(r.Context())
		if !si.User.IsAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin required", nil)
			return
		}
		next(w, r)
	})
}

var csrfExempt = map[string]bool{
	"/api/v1/auth/login":         true,
	"/api/v1/auth/oidc/callback": true,
}

// csrf enforces X-CSRF-Token on state-changing API calls that carry a session.
func (h *handlers) csrf() middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if !strings.HasPrefix(r.URL.Path, "/api/") || csrfExempt[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			si, ok := sessionFrom(r.Context())
			if !ok {
				next.ServeHTTP(w, r) // anonymous request: nothing to forge; handler decides auth
				return
			}
			if tok := r.Header.Get("X-CSRF-Token"); tok == "" || tok != si.Session.CSRFToken {
				writeError(w, http.StatusForbidden, "csrf_invalid", "missing or invalid X-CSRF-Token", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *handlers) secureCookies() bool { return strings.HasPrefix(h.cfg.AppBaseURL, "https://") }

func (h *handlers) setSessionCookie(w http.ResponseWriter, sess auth.Session) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite=Strict set; Secure derives from APP_BASE_URL scheme
		Name: sessionCookie, Value: sess.ID, Path: "/", HttpOnly: true, Secure: h.secureCookies(),
		SameSite: http.SameSiteStrictMode, Expires: sess.AbsoluteExpiry,
	})
}

func (h *handlers) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expired cookie; same flags as setSessionCookie
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: h.secureCookies(),
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}
