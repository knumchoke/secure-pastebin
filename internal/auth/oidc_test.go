package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/config"
)

type memOIDCStates struct {
	states map[string]OIDCState
	ttl    time.Duration
}

func (s *memOIDCStates) Save(_ context.Context, state string, value OIDCState, ttl time.Duration) error {
	s.states[state] = value
	s.ttl = ttl
	return nil
}

func (s *memOIDCStates) Take(_ context.Context, state string) (OIDCState, error) {
	value, ok := s.states[state]
	if !ok {
		return OIDCState{}, ErrOIDCStateInvalid
	}
	delete(s.states, state)
	return value, nil
}

type trackingOIDCUsers struct {
	*memUsers
	upserts int
}

func (u *trackingOIDCUsers) UpsertOIDC(ctx context.Context, user User) (User, error) {
	u.upserts++
	return u.memUsers.UpsertOIDC(ctx, user)
}

type fakeIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	badKey *rsa.PrivateKey

	mu                sync.Mutex
	nonce             string
	expectedChallenge string
	groups            any
	subject           any
	username          any
	email             any
	name              any
	issuer            string
	audience          any
	expiresAt         time.Time
	badSignature      bool
	missingIDToken    bool
	malformedIDToken  bool
	tokenErrorBody    string
	lastCode          string
	pkceOK            bool
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{
		key:       key,
		badKey:    badKey,
		groups:    []string{"pastebin-user"},
		subject:   "subject-123",
		username:  "bob",
		email:     "bob@example.test",
		name:      "Bob B",
		audience:  "pastebin",
		expiresAt: time.Now().Add(time.Hour),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.server.URL,
			"authorization_endpoint":                f.server.URL + "/authorize",
			"token_endpoint":                        f.server.URL + "/token",
			"jwks_uri":                              f.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &f.key.PublicKey, KeyID: "key-1", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("/token", f.serveToken)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIDP) serveToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastCode = r.Form.Get("code")
	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		clientID, clientSecret = basicID, basicSecret
	}
	f.pkceOK = r.Form.Get("grant_type") == "authorization_code" &&
		r.Form.Get("redirect_uri") == "https://pastebin.example.test/api/v1/auth/oidc/callback" &&
		clientID == "pastebin" && clientSecret == "client-secret" &&
		s256Test(r.Form.Get("code_verifier")) == f.expectedChallenge
	if f.tokenErrorBody != "" {
		http.Error(w, f.tokenErrorBody, http.StatusBadRequest)
		return
	}
	if !f.pkceOK {
		http.Error(w, "invalid token request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.missingIDToken {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer"})
		return
	}
	if f.malformedIDToken {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer", "id_token": "sensitive.raw.token"})
		return
	}

	signingKey := f.key
	if f.badSignature {
		signingKey = f.badKey
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithHeader("kid", "key-1"),
	)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	issuer := f.issuer
	if issuer == "" {
		issuer = f.server.URL
	}
	claims := map[string]any{
		"iss": issuer, "sub": f.subject, "aud": f.audience,
		"exp": f.expiresAt.Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"nonce": f.nonce, "preferred_username": f.username,
		"email": f.email, "name": f.name, "groups": f.groups,
	}
	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, "token serialization failed", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-token", "token_type": "Bearer", "id_token": idToken, "expires_in": 3600,
	})
}

func (f *fakeIDP) configureFromRedirect(t *testing.T, redirect string) url.Values {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	f.mu.Lock()
	f.nonce = q.Get("nonce")
	f.expectedChallenge = q.Get("code_challenge")
	f.mu.Unlock()
	return q
}

func oidcTestConfig(issuer string) config.OIDCConfig {
	return config.OIDCConfig{
		Issuer: issuer, ClientID: "pastebin", ClientSecret: "client-secret",
		RedirectURL:   "https://pastebin.example.test/api/v1/auth/oidc/callback",
		Scopes:        []string{"openid", "profile", "email", "groups"},
		RequiredGroup: "pastebin-user", GroupClaim: "groups", AdminGroup: "pastebin-admin",
	}
}

func newTestOIDC(t *testing.T, idp *fakeIDP, users UserStore, states *memOIDCStates, sink audit.Sink) *OIDC {
	t.Helper()
	flow, err := NewOIDC(context.Background(), oidcTestConfig(idp.server.URL), users, states, sink, idp.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func startOIDC(t *testing.T, flow *OIDC, idp *fakeIDP) url.Values {
	t.Helper()
	redirect, err := flow.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	q := idp.configureFromRedirect(t, redirect)
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL is missing state, nonce, or S256 PKCE: %s", redirect)
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorization scope = %q, want openid", q.Get("scope"))
	}
	return q
}

func TestOIDCHappyPathUsesPKCEAndSingleUseState(t *testing.T) {
	idp := newFakeIDP(t)
	users := &trackingOIDCUsers{memUsers: &memUsers{byName: map[string]User{}}}
	states := &memOIDCStates{states: map[string]OIDCState{}}
	sink := &memAudit{}
	flow := newTestOIDC(t, idp, users, states, sink)
	now := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	flow.now = func() time.Time { return now }

	q := startOIDC(t, flow, idp)
	if states.ttl != 5*time.Minute {
		t.Fatalf("state ttl = %v, want 5m", states.ttl)
	}
	for _, name := range []string{"state", "nonce"} {
		raw, err := base64.RawURLEncoding.DecodeString(q.Get(name))
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s is not 32 random bytes", name)
		}
	}
	stored := states.states[q.Get("state")]
	if raw, err := base64.RawURLEncoding.DecodeString(stored.Verifier); err != nil || len(raw) != 32 {
		t.Fatal("verifier is not 32 random bytes")
	}
	if stored.Nonce != q.Get("nonce") || !stored.CreatedAt.Equal(now) {
		t.Fatal("stored state does not match authorization request")
	}

	got, err := flow.Complete(context.Background(), q.Get("state"), "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "bob" || got.DisplayName != "Bob B" || got.Provider != ProviderOIDC || got.OIDCIssuer != idp.server.URL || got.OIDCSubject != "subject-123" || got.IsAdmin {
		t.Fatalf("user = %+v", got)
	}
	idp.mu.Lock()
	pkceOK, code := idp.pkceOK, idp.lastCode
	idp.mu.Unlock()
	if !pkceOK || code != "authorization-code" {
		t.Fatal("token exchange did not use the supplied code and matching verifier")
	}
	if users.upserts != 1 {
		t.Fatalf("upserts = %d, want 1", users.upserts)
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(sink.events))
	}
	event := sink.events[0]
	if event.Event != audit.OIDCLogin || event.Outcome != audit.OutcomeSuccess || event.ActorID == nil || *event.ActorID != got.ID {
		t.Fatalf("audit event = %+v", event)
	}
	if len(event.Details) != 2 || event.Details["provider"] != "oidc" || event.Details["is_admin"] != false {
		t.Fatalf("audit details = %+v", event.Details)
	}

	if _, err := flow.Complete(context.Background(), q.Get("state"), "authorization-code"); !errors.Is(err, ErrOIDCStateInvalid) {
		t.Fatalf("replay error = %v, want ErrOIDCStateInvalid", err)
	}
}

func TestOIDCRejectsExpiredOrMalformedStateBeforeExchange(t *testing.T) {
	idp := newFakeIDP(t)
	for _, tc := range []struct {
		name   string
		mutate func(*OIDCState, time.Time)
	}{
		{name: "expired", mutate: func(st *OIDCState, now time.Time) { st.CreatedAt = now.Add(-5 * time.Minute) }},
		{name: "future", mutate: func(st *OIDCState, now time.Time) { st.CreatedAt = now.Add(time.Second) }},
		{name: "missing verifier", mutate: func(st *OIDCState, _ time.Time) { st.Verifier = "" }},
		{name: "missing nonce", mutate: func(st *OIDCState, _ time.Time) { st.Nonce = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			states := &memOIDCStates{states: map[string]OIDCState{}}
			flow := newTestOIDC(t, idp, &memUsers{byName: map[string]User{}}, states, &memAudit{})
			now := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
			flow.now = func() time.Time { return now }
			q := startOIDC(t, flow, idp)
			st := states.states[q.Get("state")]
			tc.mutate(&st, now)
			states.states[q.Get("state")] = st
			if _, err := flow.Complete(context.Background(), q.Get("state"), "code"); !errors.Is(err, ErrOIDCStateInvalid) {
				t.Fatalf("error = %v, want ErrOIDCStateInvalid", err)
			}
		})
	}
}

func TestOIDCGroupGateRunsBeforeProvisioning(t *testing.T) {
	idp := newFakeIDP(t)
	idp.groups = []string{"other-group"}
	users := &trackingOIDCUsers{memUsers: &memUsers{byName: map[string]User{}}}
	sink := &memAudit{}
	flow := newTestOIDC(t, idp, users, &memOIDCStates{states: map[string]OIDCState{}}, sink)
	q := startOIDC(t, flow, idp)

	if _, err := flow.Complete(context.Background(), q.Get("state"), "code"); !errors.Is(err, ErrNotAuthorised) {
		t.Fatalf("error = %v, want ErrNotAuthorised", err)
	}
	if users.upserts != 0 || len(users.byName) != 0 {
		t.Fatal("group-denied identity was provisioned")
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(sink.events))
	}
	event := sink.events[0]
	if event.Event != audit.OIDCDenied || event.Outcome != audit.OutcomeDenied || len(event.Details) != 3 ||
		event.Details["reason"] != "missing_required_group" || event.Details["issuer"] != idp.server.URL || event.Details["subject"] != "subject-123" {
		t.Fatalf("denied audit = %+v", event)
	}
}

func TestOIDCAdminMembershipIsAddedAndRemovedEachLogin(t *testing.T) {
	idp := newFakeIDP(t)
	idp.groups = []string{"pastebin-user", "pastebin-admin"}
	users := &trackingOIDCUsers{memUsers: &memUsers{byName: map[string]User{}}}
	flow := newTestOIDC(t, idp, users, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{})

	q := startOIDC(t, flow, idp)
	first, err := flow.Complete(context.Background(), q.Get("state"), "code")
	if err != nil || !first.IsAdmin {
		t.Fatalf("admin login = (%+v, %v)", first, err)
	}
	idp.mu.Lock()
	idp.groups = []string{"pastebin-user"}
	idp.mu.Unlock()
	q = startOIDC(t, flow, idp)
	second, err := flow.Complete(context.Background(), q.Get("state"), "code")
	if err != nil || second.IsAdmin || second.ID != first.ID {
		t.Fatalf("non-admin relogin = (%+v, %v), first ID %s", second, err, first.ID)
	}
}

func TestOIDCDisabledUserIsDenied(t *testing.T) {
	idp := newFakeIDP(t)
	existing := User{
		ID: uuid.New(), Username: "bob", Provider: ProviderOIDC,
		OIDCIssuer: idp.server.URL, OIDCSubject: "subject-123", Disabled: true,
	}
	users := &trackingOIDCUsers{memUsers: &memUsers{byName: map[string]User{"bob": existing}}}
	sink := &memAudit{}
	flow := newTestOIDC(t, idp, users, &memOIDCStates{states: map[string]OIDCState{}}, sink)
	q := startOIDC(t, flow, idp)

	if _, err := flow.Complete(context.Background(), q.Get("state"), "code"); !errors.Is(err, ErrNotAuthorised) {
		t.Fatalf("error = %v, want ErrNotAuthorised", err)
	}
	if len(sink.events) != 1 || sink.events[0].Details["reason"] != "disabled" {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

func TestOIDCRejectsNonceAndTokenValidationFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeIDP)
	}{
		{name: "nonce", mutate: func(idp *fakeIDP) { idp.nonce = "wrong-nonce" }},
		{name: "signature", mutate: func(idp *fakeIDP) { idp.badSignature = true }},
		{name: "issuer", mutate: func(idp *fakeIDP) { idp.issuer = "https://wrong-issuer.example.test" }},
		{name: "audience", mutate: func(idp *fakeIDP) { idp.audience = "wrong-client" }},
		{name: "expiry", mutate: func(idp *fakeIDP) { idp.expiresAt = time.Now().Add(-time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			users := &trackingOIDCUsers{memUsers: &memUsers{byName: map[string]User{}}}
			flow := newTestOIDC(t, idp, users, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{})
			q := startOIDC(t, flow, idp)
			idp.mu.Lock()
			tc.mutate(idp)
			idp.mu.Unlock()
			if _, err := flow.Complete(context.Background(), q.Get("state"), "code"); err == nil {
				t.Fatal("invalid token was accepted")
			}
			if users.upserts != 0 {
				t.Fatal("invalid token provisioned a user")
			}
		})
	}
}

func TestOIDCRejectsMissingIdentityAndMalformedClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeIDP)
	}{
		{name: "empty subject", mutate: func(idp *fakeIDP) { idp.subject = "" }},
		{name: "malformed subject", mutate: func(idp *fakeIDP) { idp.subject = []string{"bad"} }},
		{name: "malformed username", mutate: func(idp *fakeIDP) { idp.username = []string{"bad"} }},
		{name: "malformed groups", mutate: func(idp *fakeIDP) { idp.groups = "pastebin-user" }},
		{name: "mixed groups", mutate: func(idp *fakeIDP) { idp.groups = []any{"pastebin-user", 7} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			tc.mutate(idp)
			users := &trackingOIDCUsers{memUsers: &memUsers{byName: map[string]User{}}}
			flow := newTestOIDC(t, idp, users, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{})
			q := startOIDC(t, flow, idp)
			if _, err := flow.Complete(context.Background(), q.Get("state"), "code"); err == nil {
				t.Fatal("malformed identity was accepted")
			}
			if users.upserts != 0 {
				t.Fatal("malformed identity provisioned a user")
			}
		})
	}
}

func TestOIDCUsernameFallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		username any
		email    any
		want     string
	}{
		{name: "email", username: "", email: "bob@example.test", want: "bob@example.test"},
		{name: "subject", username: "", email: "", want: "subject-123"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			idp.username, idp.email = tc.username, tc.email
			flow := newTestOIDC(t, idp, &memUsers{byName: map[string]User{}}, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{})
			q := startOIDC(t, flow, idp)
			got, err := flow.Complete(context.Background(), q.Get("state"), "code")
			if err != nil || got.Username != tc.want {
				t.Fatalf("user = (%+v, %v), want username %q", got, err, tc.want)
			}
		})
	}
}

func TestOIDCErrorsDoNotExposeProviderBodiesOrTokens(t *testing.T) {
	const secret = "provider-body-secret client-secret authorization-code sensitive.raw.token"
	for _, tc := range []struct {
		name   string
		mutate func(*fakeIDP)
	}{
		{name: "exchange", mutate: func(idp *fakeIDP) { idp.tokenErrorBody = secret }},
		{name: "verification", mutate: func(idp *fakeIDP) { idp.malformedIDToken = true }},
		{name: "missing id token", mutate: func(idp *fakeIDP) { idp.missingIDToken = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			flow := newTestOIDC(t, idp, &memUsers{byName: map[string]User{}}, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{})
			q := startOIDC(t, flow, idp)
			tc.mutate(idp)
			_, err := flow.Complete(context.Background(), q.Get("state"), "authorization-code")
			if err == nil {
				t.Fatal("provider failure was accepted")
			}
			for _, marker := range strings.Fields(secret) {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("error exposed %q: %v", marker, err)
				}
			}
		})
	}
}

func TestNewOIDCRequiresGroupAndSanitizesDiscoveryErrors(t *testing.T) {
	cfg := oidcTestConfig("https://idp.invalid")
	cfg.RequiredGroup = "  "
	flow, err := NewOIDC(context.Background(), cfg, &memUsers{byName: map[string]User{}}, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{}, nil)
	if flow != nil || err == nil {
		t.Fatal("blank required group was accepted")
	}

	const secret = "discovery-provider-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, secret, http.StatusInternalServerError)
	}))
	defer server.Close()
	cfg = oidcTestConfig(server.URL)
	flow, err = NewOIDC(context.Background(), cfg, &memUsers{byName: map[string]User{}}, &memOIDCStates{states: map[string]OIDCState{}}, &memAudit{}, server.Client())
	if flow != nil || err == nil {
		t.Fatal("failed discovery returned a flow")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("discovery error exposed response body: %v", err)
	}
}

func s256Test(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
