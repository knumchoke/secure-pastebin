package httpserver

import (
	"log/slog"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/challenge"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/paste"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

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
