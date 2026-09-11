package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var testKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func minimal() map[string]string {
	return map[string]string{ // #nosec G101 -- dummy test credentials
		"APP_BASE_URL": "https://pastebin.internal.example",
		"DATABASE_URL": "postgres://u:p@db/pastebin",
		"REDIS_URL":    "redis://:pw@redis:6379/0",
		"MASTER_KEYS":  "k1:" + testKey,
	}
}

func TestLoad_Defaults(t *testing.T) {
	c, err := Load(env(minimal()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8443" || c.AuthMode != AuthLocal || !c.Challenge.Enabled {
		t.Errorf("defaults wrong: %+v", c)
	}
	if c.PasteMaxSize != 256<<10 || c.PasteTTLDefault != 300 || c.PasteTTLMin != 30 || c.PasteTTLMax != 900 {
		t.Errorf("paste defaults wrong: %+v", c)
	}
	if c.Argon2.MaxConcurrent != 4 || c.Argon2.MemoryKiB != 32768 || c.Argon2.Time != 3 || c.Argon2.Threads != 2 {
		t.Errorf("argon2 defaults wrong: %+v", c.Argon2)
	}
	if c.SessionIdleTTL != 8*time.Hour || c.SessionAbsoluteTTL != 12*time.Hour {
		t.Errorf("session defaults wrong")
	}
	if c.MasterKeyActive != "k1" || len(c.MasterKeys["k1"]) != 32 {
		t.Errorf("master key not loaded")
	}
	if c.RedisStateURL != c.RedisURL {
		t.Errorf("RedisStateURL should default to RedisURL")
	}
	if c.Rate.PastePerMin != 10 || c.Rate.UnlockPer15Min != 5 || c.Rate.VerifyGlobalPerMin != 300 {
		t.Errorf("rate defaults wrong: %+v", c.Rate)
	}
	if c.MetadataRetentionDays != 180 || c.AuditRetentionDays != 365 {
		t.Errorf("retention defaults wrong")
	}
	if c.OIDC.RedirectURL != "https://pastebin.internal.example/api/v1/auth/oidc/callback" {
		t.Errorf("redirect url = %q", c.OIDC.RedirectURL)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	for _, k := range []string{"APP_BASE_URL", "DATABASE_URL", "REDIS_URL", "MASTER_KEYS"} {
		m := minimal()
		delete(m, k)
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("missing %s: err = %v", k, err)
		}
	}
}

func TestLoad_MasterKeysFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "master_keys")
	if err := os.WriteFile(f, []byte("a:"+testKey+",b:"+testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := minimal()
	delete(m, "MASTER_KEYS")
	m["MASTER_KEYS_FILE"] = f
	m["MASTER_KEY_ACTIVE"] = "b"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MasterKeys) != 2 || c.MasterKeyActive != "b" {
		t.Errorf("got %+v", c.MasterKeys)
	}
}

func TestLoad_BothMasterKeySourcesRejected(t *testing.T) {
	m := minimal()
	m["MASTER_KEYS_FILE"] = "/nonexistent"
	if _, err := Load(env(m)); err == nil {
		t.Error("expected error when both MASTER_KEYS and MASTER_KEYS_FILE set")
	}
}

func TestParseMasterKeys_Errors(t *testing.T) {
	bad := []string{"", "k1", "k1:notbase64!", "k1:" + base64.StdEncoding.EncodeToString([]byte("short")), "k1:" + testKey + ",k1:" + testKey}
	for _, s := range bad {
		if _, _, err := ParseMasterKeys(s); err == nil {
			t.Errorf("ParseMasterKeys(%q) expected error", s)
		}
	}
}

func TestLoad_ActiveKeyMustExist(t *testing.T) {
	m := minimal()
	m["MASTER_KEY_ACTIVE"] = "nope"
	if _, err := Load(env(m)); err == nil {
		t.Error("expected error for unknown active key")
	}
}

func TestLoad_OIDCRequiresGroup(t *testing.T) {
	m := minimal()
	m["AUTH_MODE"] = "oidc"
	m["OIDC_ISSUER"] = "https://idp/realms/x"
	m["OIDC_CLIENT_ID"] = "pastebin"
	m["OIDC_CLIENT_SECRET"] = "s"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "OIDC_REQUIRED_GROUP") {
		t.Errorf("err = %v", err)
	}
	m["OIDC_REQUIRED_GROUP"] = "pastebin-user"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC.GroupClaim != "groups" || strings.Join(c.OIDC.Scopes, " ") != "openid profile email groups" {
		t.Errorf("oidc defaults: %+v", c.OIDC)
	}
	if !c.OIDCEnabled() || c.LocalEnabled() {
		t.Error("mode flags wrong")
	}
}

func TestLoad_TTLValidation(t *testing.T) {
	cases := []map[string]string{
		{"PASTE_TTL_MAX": "901"},
		{"PASTE_TTL_MIN": "10", "PASTE_TTL_DEFAULT": "5"},
		{"PASTE_TTL_MIN": "500", "PASTE_TTL_MAX": "400"},
		{"PASTE_TTL_DEFAULT": "0"},
	}
	for _, extra := range cases {
		m := minimal()
		for k, v := range extra {
			m[k] = v
		}
		if _, err := Load(env(m)); err == nil {
			t.Errorf("expected error for %v", extra)
		}
	}
	m := minimal()
	m["PASTE_TTL_HARD_MAX"] = "1800"
	m["PASTE_TTL_MAX"] = "1200"
	if _, err := Load(env(m)); err != nil {
		t.Errorf("raising hard max should allow 1200: %v", err)
	}
}

func TestLoad_PasteMaxSize(t *testing.T) {
	m := minimal()
	m["PASTE_MAX_SIZE"] = "1024KB"
	c, err := Load(env(m))
	if err != nil || c.PasteMaxSize != 1<<20 {
		t.Fatalf("got %d, %v", c.PasteMaxSize, err)
	}
	m["PASTE_MAX_SIZE"] = "1GB"
	if _, err := Load(env(m)); err == nil {
		t.Error("expected error")
	}
}

func TestLoad_TrustedProxyCIDRs(t *testing.T) {
	m := minimal()
	m["TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8, 192.168.1.0/24"
	c, err := Load(env(m))
	if err != nil || len(c.TrustedProxyCIDRs) != 2 {
		t.Fatalf("got %v %v", c.TrustedProxyCIDRs, err)
	}
	m["TRUSTED_PROXY_CIDRS"] = "nope"
	if _, err := Load(env(m)); err == nil {
		t.Error("bad cidr must fail")
	}
}

func TestLoad_TLSPairRequired(t *testing.T) {
	m := minimal()
	m["TLS_CERT_FILE"] = "/c.pem"
	if _, err := Load(env(m)); err == nil {
		t.Error("cert without key must fail")
	}
}

func TestRedacted(t *testing.T) {
	c, _ := Load(env(minimal()))
	r := c.Redacted()
	for _, k := range []string{"DatabaseURL", "RedisURL", "RedisStateURL", "MasterKeys", "OIDCClientSecret"} {
		v, ok := r[k]
		if !ok {
			t.Errorf("missing %s", k)
			continue
		}
		if s, _ := v.(string); strings.Contains(s, "pw") || strings.Contains(s, testKey) || strings.Contains(s, "u:p@") {
			t.Errorf("%s not redacted: %v", k, v)
		}
	}
}

func TestRecommendedRedisMaxMemory(t *testing.T) {
	c, _ := Load(env(minimal()))
	// 256KiB * 10 * 15 * 50 * 1.2 + 64MiB
	want := int64(float64(256<<10)*10*15*50*1.2) + 64<<20
	if got := c.RecommendedRedisMaxMemory(); got != want {
		t.Errorf("got %d want %d", got, want)
	}
}
