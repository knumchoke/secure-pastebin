package httpserver

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/challenge"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/paste"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

// Deps are the ports the HTTP layer needs. Nil optional ports disable features.
type Deps struct {
	Cfg      *config.Config
	Log      *slog.Logger
	Pastes   paste.Service
	Users    auth.UserStore
	Sessions auth.SessionStore
	Local    auth.LocalAuthenticator
	OIDC     auth.OIDCFlow
	Chal     challenge.Challenger
	Limiter  ratelimit.Limiter
	Audit    audit.Sink
	Ready    map[string]func(context.Context) error
	Static   fs.FS
	Metrics  *Metrics
	Now      func() time.Time
}

type handlers struct {
	cfg      *config.Config
	log      *slog.Logger
	pastes   paste.Service
	users    auth.UserStore
	sessions auth.SessionStore
	local    auth.LocalAuthenticator
	oidc     auth.OIDCFlow
	chal     challenge.Challenger
	limiter  ratelimit.Limiter
	audit    audit.Sink
	metrics  *Metrics
	now      func() time.Time
}

const smallBody = 64 << 10

// NewHandler builds the full HTTP handler (API + SPA + health).
func NewHandler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.Metrics == nil {
		d.Metrics = NewMetrics()
	}
	h := &handlers{cfg: d.Cfg, log: d.Log, pastes: d.Pastes, users: d.Users, sessions: d.Sessions, local: d.Local,
		oidc: d.OIDC, chal: d.Chal, limiter: d.Limiter, audit: d.Audit, metrics: d.Metrics, now: d.Now}

	api := http.NewServeMux()
	small := func(fn http.HandlerFunc) http.Handler { return chain(fn, maxBody(smallBody)) }
	api.Handle("GET /api/v1/config", small(h.getConfig))
	api.Handle("POST /api/v1/auth/login", small(h.login))
	api.Handle("POST /api/v1/auth/logout", small(h.requireAuth(h.logout)))
	api.Handle("GET /api/v1/auth/me", small(h.requireAuth(h.me)))
	api.Handle("GET /api/v1/auth/oidc/start", small(h.oidcStart))
	api.Handle("GET /api/v1/auth/oidc/callback", small(h.oidcCallback))
	api.Handle("POST /api/v1/challenges", small(h.requireAuth(h.issueChallenge)))
	api.Handle("POST /api/v1/challenges/{id}/verify", small(h.requireAuth(h.verifyChallenge)))
	api.Handle("POST /api/v1/pastes", chain(h.requireAuth(h.createPaste), maxBody(6*d.Cfg.PasteMaxSize+smallBody)))
	api.Handle("GET /api/v1/pastes/{id}", small(h.viewGate(h.getPaste)))
	api.Handle("DELETE /api/v1/pastes/{id}", small(h.requireAuth(h.deletePaste)))
	api.Handle("POST /api/v1/pastes/{id}/unlock", small(h.viewGate(h.unlockPaste)))
	api.Handle("GET /api/v1/pastes/{id}/raw", small(h.viewGate(h.rawPaste)))
	api.Handle("POST /api/v1/pastes/{id}/verify", small(h.viewGate(h.verifyPaste)))
	api.Handle("GET /api/v1/me/pastes", small(h.requireAuth(h.listMine)))
	api.Handle("GET /api/v1/admin/pastes", small(h.requireAdmin(h.adminList)))
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint", nil)
	})

	root := http.NewServeMux()
	root.Handle("GET /healthz", HealthHandler())
	root.Handle("GET /readyz", ReadyHandler(d.Ready))
	root.Handle("/api/", api)
	if d.Static != nil {
		root.Handle("/", spaHandler(d.Static))
	}

	hsts := d.Cfg.TLSCertFile != "" || strings.HasPrefix(d.Cfg.AppBaseURL, "https://")
	return chain(root,
		recoverer(d.Log),
		requestID(),
		clientIP(d.Cfg.TrustedProxyCIDRs),
		securityHeaders(hsts),
		httpMetrics(d.Metrics),
		accessLog(d.Log),
		h.loadSession(),
		h.csrf(),
	)
}

// viewGate requires a session only when VIEW_REQUIRES_AUTH is set (spec D7).
func (h *handlers) viewGate(next http.HandlerFunc) http.HandlerFunc {
	if h.cfg.ViewRequiresAuth {
		return h.requireAuth(next)
	}
	return next
}
