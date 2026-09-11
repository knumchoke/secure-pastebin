// Package config loads and validates all runtime configuration from the
// environment (spec §12). It performs no I/O other than reading the
// optional *_FILE secrets.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type AuthMode string

const (
	AuthLocal AuthMode = "local"
	AuthOIDC  AuthMode = "oidc"
	AuthBoth  AuthMode = "both"
)

type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	RequiredGroup string
	GroupClaim    string
	AdminGroup    string
}

type ChallengeConfig struct {
	Enabled     bool
	TolerancePx int
	TTL         time.Duration
	MinSolve    time.Duration
}

type Argon2Config struct {
	MaxConcurrent int
	QueueTimeout  time.Duration
	MemoryKiB     uint32
	Time          uint32
	Threads       uint8
}

type RateConfig struct {
	PastePerMin        int
	LoginPerMin        int
	LoginIPPerMin      int
	UnlockPer15Min     int
	UnlockIPPer15Min   int
	VerifyPerMin       int
	VerifyGlobalPerMin int
	ChallengePerMin    int
	DeletePerMin       int
}

type Config struct {
	AppBaseURL            string
	ListenAddr            string
	TrustedProxyCIDRs     []netip.Prefix
	TLSCertFile           string
	TLSKeyFile            string
	DatabaseURL           string
	RedisURL              string
	RedisStateURL         string
	MasterKeys            map[string][]byte
	MasterKeyActive       string
	AuthMode              AuthMode
	OIDC                  OIDCConfig
	SessionIdleTTL        time.Duration
	SessionAbsoluteTTL    time.Duration
	ViewRequiresAuth      bool
	Challenge             ChallengeConfig
	Argon2                Argon2Config
	PasteMaxSize          int64
	PasteTTLDefault       int
	PasteTTLMin           int
	PasteTTLMax           int
	PasteTTLHardMax       int
	MetadataRetentionDays int
	AuditRetentionDays    int
	Rate                  RateConfig
	RedisExpectedUsers    int
	AuditDBEnabled        bool
	LogLevel              string
	MetricsListenAddr     string
	NoticeText            string
}

// loader accumulates parse errors so the operator sees all of them at once.
type loader struct {
	getenv func(string) string
	errs   []string
}

func (l *loader) str(key, def string) string {
	if v := strings.TrimSpace(l.getenv(key)); v != "" {
		return v
	}
	return def
}

func (l *loader) required(key string) string {
	v := strings.TrimSpace(l.getenv(key))
	if v == "" {
		l.errs = append(l.errs, key+" is required")
	}
	return v
}

func (l *loader) intv(key string, def int) int {
	v := strings.TrimSpace(l.getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errs = append(l.errs, key+": not an integer")
		return def
	}
	return n
}

func (l *loader) boolv(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(l.getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	l.errs = append(l.errs, key+": not a boolean")
	return def
}

func (l *loader) dur(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(l.getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errs = append(l.errs, key+": not a duration (e.g. 8h, 2s)")
		return def
	}
	return d
}

// secret reads KEY or KEY_FILE (exactly one). Returns "" if neither set.
func (l *loader) secret(key string) string {
	inline := strings.TrimSpace(l.getenv(key))
	file := strings.TrimSpace(l.getenv(key + "_FILE"))
	switch {
	case inline != "" && file != "":
		l.errs = append(l.errs, fmt.Sprintf("set only one of %s / %s_FILE", key, key))
		return ""
	case file != "":
		b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied secrets path
		if err != nil {
			l.errs = append(l.errs, fmt.Sprintf("%s_FILE: %v", key, err))
			return ""
		}
		return strings.TrimSpace(string(b))
	default:
		return inline
	}
}

// ParseMasterKeys parses "id:base64(32B)[,id:base64…]". IDs must be unique.
func ParseMasterKeys(s string) (map[string][]byte, string, error) {
	keys := map[string][]byte{}
	first := ""
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64, ok := strings.Cut(part, ":")
		if !ok || id == "" {
			return nil, "", errors.New("master key entry must be id:base64")
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, "", fmt.Errorf("master key %q: invalid base64", id)
		}
		if len(raw) != 32 {
			return nil, "", fmt.Errorf("master key %q: must be 32 bytes, got %d", id, len(raw))
		}
		if _, dup := keys[id]; dup {
			return nil, "", fmt.Errorf("master key %q: duplicate id", id)
		}
		if first == "" {
			first = id
		}
		keys[id] = raw
	}
	if len(keys) == 0 {
		return nil, "", errors.New("no master keys")
	}
	return keys, first, nil
}

// Load reads configuration from getenv (usually os.Getenv) and validates it.
func Load(getenv func(string) string) (*Config, error) {
	l := &loader{getenv: getenv}
	c := &Config{}

	c.AppBaseURL = strings.TrimRight(l.required("APP_BASE_URL"), "/")
	c.ListenAddr = l.str("LISTEN_ADDR", ":8443")
	for _, cidr := range strings.Split(l.str("TRUSTED_PROXY_CIDRS", ""), ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			l.errs = append(l.errs, "TRUSTED_PROXY_CIDRS: bad cidr "+cidr)
			continue
		}
		c.TrustedProxyCIDRs = append(c.TrustedProxyCIDRs, pfx)
	}
	c.TLSCertFile = l.str("TLS_CERT_FILE", "")
	c.TLSKeyFile = l.str("TLS_KEY_FILE", "")
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		l.errs = append(l.errs, "TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	c.DatabaseURL = l.required("DATABASE_URL")
	c.RedisURL = l.required("REDIS_URL")
	c.RedisStateURL = l.str("REDIS_STATE_URL", c.RedisURL)

	errsBefore := len(l.errs)
	mk := l.secret("MASTER_KEYS")
	switch {
	case len(l.errs) > errsBefore:
		// secret() already reported the problem (both sources set / unreadable file)
	case mk == "":
		l.errs = append(l.errs, "MASTER_KEYS or MASTER_KEYS_FILE is required")
	default:
		keys, first, err := ParseMasterKeys(mk)
		if err != nil {
			l.errs = append(l.errs, "MASTER_KEYS: "+err.Error())
			break
		}
		c.MasterKeys = keys
		c.MasterKeyActive = l.str("MASTER_KEY_ACTIVE", first)
		if _, ok := keys[c.MasterKeyActive]; !ok {
			l.errs = append(l.errs, "MASTER_KEY_ACTIVE: unknown key id "+c.MasterKeyActive)
		}
	}

	c.AuthMode = AuthMode(strings.ToLower(l.str("AUTH_MODE", string(AuthLocal))))
	switch c.AuthMode {
	case AuthLocal, AuthOIDC, AuthBoth:
	default:
		l.errs = append(l.errs, "AUTH_MODE must be local, oidc or both")
	}
	c.OIDC = OIDCConfig{
		Issuer:        l.str("OIDC_ISSUER", ""),
		ClientID:      l.str("OIDC_CLIENT_ID", ""),
		ClientSecret:  l.secret("OIDC_CLIENT_SECRET"),
		RedirectURL:   c.AppBaseURL + "/api/v1/auth/oidc/callback",
		Scopes:        strings.Fields(l.str("OIDC_SCOPES", "openid profile email groups")),
		RequiredGroup: l.str("OIDC_REQUIRED_GROUP", ""),
		GroupClaim:    l.str("OIDC_GROUP_CLAIM", "groups"),
		AdminGroup:    l.str("OIDC_ADMIN_GROUP", ""),
	}
	if c.OIDCEnabled() {
		for k, v := range map[string]string{
			"OIDC_ISSUER": c.OIDC.Issuer, "OIDC_CLIENT_ID": c.OIDC.ClientID,
			"OIDC_CLIENT_SECRET": c.OIDC.ClientSecret, "OIDC_REQUIRED_GROUP": c.OIDC.RequiredGroup,
		} {
			if v == "" {
				l.errs = append(l.errs, k+" is required when AUTH_MODE includes oidc")
			}
		}
	}

	c.SessionIdleTTL = l.dur("SESSION_IDLE_TTL", 8*time.Hour)
	c.SessionAbsoluteTTL = l.dur("SESSION_ABSOLUTE_TTL", 12*time.Hour)
	if c.SessionAbsoluteTTL < c.SessionIdleTTL {
		l.errs = append(l.errs, "SESSION_ABSOLUTE_TTL must be >= SESSION_IDLE_TTL")
	}
	c.ViewRequiresAuth = l.boolv("VIEW_REQUIRES_AUTH", false)

	c.Challenge = ChallengeConfig{
		Enabled:     l.boolv("CHALLENGE_ENABLED", true),
		TolerancePx: l.intv("CHALLENGE_TOLERANCE_PX", 5),
		TTL:         time.Duration(l.intv("CHALLENGE_TTL_SECONDS", 120)) * time.Second,
		MinSolve:    time.Duration(l.intv("CHALLENGE_MIN_SOLVE_MS", 300)) * time.Millisecond,
	}
	c.Argon2 = Argon2Config{
		MaxConcurrent: l.intv("ARGON2_MAX_CONCURRENT", 4),
		QueueTimeout:  l.dur("ARGON2_QUEUE_TIMEOUT", 2*time.Second),
		MemoryKiB:     uint32(l.intv("ARGON2_MEMORY_KIB", 32768)), // #nosec G115 -- validated below
		Time:          3,
		Threads:       2,
	}
	if c.Argon2.MaxConcurrent < 1 || c.Argon2.MemoryKiB < 8192 {
		l.errs = append(l.errs, "ARGON2_MAX_CONCURRENT must be >= 1 and ARGON2_MEMORY_KIB >= 8192")
	}

	if v := l.str("PASTE_MAX_SIZE", "256KB"); v != "" {
		n, err := ParseSize(v)
		if err != nil {
			l.errs = append(l.errs, "PASTE_MAX_SIZE: "+err.Error())
		}
		c.PasteMaxSize = n
	}
	c.PasteTTLHardMax = l.intv("PASTE_TTL_HARD_MAX", 900)
	c.PasteTTLDefault = l.intv("PASTE_TTL_DEFAULT", 300)
	c.PasteTTLMin = l.intv("PASTE_TTL_MIN", 30)
	c.PasteTTLMax = l.intv("PASTE_TTL_MAX", 900)
	switch {
	case c.PasteTTLMin < 1:
		l.errs = append(l.errs, "PASTE_TTL_MIN must be >= 1")
	case c.PasteTTLMax > c.PasteTTLHardMax:
		l.errs = append(l.errs, fmt.Sprintf("PASTE_TTL_MAX %d exceeds PASTE_TTL_HARD_MAX %d", c.PasteTTLMax, c.PasteTTLHardMax))
	case c.PasteTTLMin > c.PasteTTLMax:
		l.errs = append(l.errs, "PASTE_TTL_MIN must be <= PASTE_TTL_MAX")
	case c.PasteTTLDefault < c.PasteTTLMin || c.PasteTTLDefault > c.PasteTTLMax:
		l.errs = append(l.errs, "PASTE_TTL_DEFAULT must be within [PASTE_TTL_MIN, PASTE_TTL_MAX]")
	}

	c.MetadataRetentionDays = l.intv("METADATA_RETENTION_DAYS", 180)
	c.AuditRetentionDays = l.intv("AUDIT_RETENTION_DAYS", 365)
	c.Rate = RateConfig{
		PastePerMin:        l.intv("RATE_PASTE_PER_MIN", 10),
		LoginPerMin:        l.intv("RATE_LOGIN_PER_MIN", 5),
		LoginIPPerMin:      l.intv("RATE_LOGIN_IP_PER_MIN", 20),
		UnlockPer15Min:     l.intv("RATE_UNLOCK_PER_15MIN", 5),
		UnlockIPPer15Min:   l.intv("RATE_UNLOCK_IP_PER_15MIN", 20),
		VerifyPerMin:       l.intv("RATE_VERIFY_PER_MIN", 30),
		VerifyGlobalPerMin: l.intv("RATE_VERIFY_GLOBAL_PER_MIN", 300),
		ChallengePerMin:    l.intv("RATE_CHALLENGE_PER_MIN", 5),
		DeletePerMin:       l.intv("RATE_DELETE_PER_MIN", 30),
	}
	c.RedisExpectedUsers = l.intv("REDIS_EXPECTED_USERS", 50)
	c.AuditDBEnabled = l.boolv("AUDIT_DB_ENABLED", true)
	c.LogLevel = strings.ToLower(l.str("LOG_LEVEL", "info"))
	c.MetricsListenAddr = l.str("METRICS_LISTEN_ADDR", "127.0.0.1:9090")
	c.NoticeText = l.str("NOTICE_TEXT", "Do not paste production credentials or customer personal data. Pastes are ephemeral, not a secure vault.")

	if len(l.errs) > 0 {
		return nil, errors.New("config: " + strings.Join(l.errs, "; "))
	}
	return c, nil
}

func (c *Config) OIDCEnabled() bool  { return c.AuthMode == AuthOIDC || c.AuthMode == AuthBoth }
func (c *Config) LocalEnabled() bool { return c.AuthMode == AuthLocal || c.AuthMode == AuthBoth }

// RecommendedRedisMaxMemory implements the sizing formula in spec §13.
func (c *Config) RecommendedRedisMaxMemory() int64 {
	bodies := float64(c.PasteMaxSize) * float64(c.Rate.PastePerMin) * 15 * float64(c.RedisExpectedUsers) * 1.2
	return int64(bodies) + 64<<20
}

// Redacted returns a log-safe view of the config.
func (c *Config) Redacted() map[string]any {
	ids := make([]string, 0, len(c.MasterKeys))
	for id := range c.MasterKeys {
		ids = append(ids, id)
	}
	return map[string]any{
		"AppBaseURL":       c.AppBaseURL,
		"ListenAddr":       c.ListenAddr,
		"TLS":              c.TLSCertFile != "",
		"DatabaseURL":      "[redacted]",
		"RedisURL":         "[redacted]",
		"RedisStateURL":    "[redacted]",
		"MasterKeys":       fmt.Sprintf("%d key(s) %v active=%s", len(ids), ids, c.MasterKeyActive),
		"AuthMode":         c.AuthMode,
		"OIDCIssuer":       c.OIDC.Issuer,
		"OIDCClientSecret": "[redacted]",
		"ViewRequiresAuth": c.ViewRequiresAuth,
		"ChallengeEnabled": c.Challenge.Enabled,
		"PasteMaxSize":     FormatSize(c.PasteMaxSize),
		"PasteTTL":         fmt.Sprintf("default=%d min=%d max=%d", c.PasteTTLDefault, c.PasteTTLMin, c.PasteTTLMax),
		"Argon2":           c.Argon2,
		"Rate":             c.Rate,
	}
}
