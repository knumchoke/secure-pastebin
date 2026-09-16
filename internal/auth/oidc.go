package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/config"
)

const oidcStateTTL = 5 * time.Minute

// OIDCState is the server-side half of an in-flight authorization request.
type OIDCState struct {
	Verifier  string    `json:"verifier"`
	Nonce     string    `json:"nonce"`
	CreatedAt time.Time `json:"created_at"`
}

// OIDCStateStore persists short-lived authorization state. Take must consume a
// state atomically and return ErrOIDCStateInvalid when it is absent or invalid.
type OIDCStateStore interface {
	Save(ctx context.Context, state string, value OIDCState, ttl time.Duration) error
	Take(ctx context.Context, state string) (OIDCState, error)
}

// OIDC implements authorization code login with S256 PKCE and a mandatory
// group gate.
type OIDC struct {
	cfg      config.OIDCConfig
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	users    UserStore
	states   OIDCStateStore
	sink     audit.Sink
	client   *http.Client
	now      func() time.Time
}

var _ OIDCFlow = (*OIDC)(nil)

// NewOIDC discovers the provider and prepares its ID-token verifier. Provider
// response details are deliberately omitted from returned errors because the
// HTTP layer logs them.
func NewOIDC(
	ctx context.Context,
	cfg config.OIDCConfig,
	users UserStore,
	states OIDCStateStore,
	sink audit.Sink,
	httpClient *http.Client,
) (*OIDC, error) {
	if strings.TrimSpace(cfg.RequiredGroup) == "" {
		return nil, errors.New("oidc: required group must be set")
	}
	discoveryCtx := withOIDCHTTPClient(ctx, httpClient)
	provider, err := oidc.NewProvider(discoveryCtx, cfg.Issuer)
	if err != nil {
		return nil, sanitizedOIDCError("discovery", err)
	}
	return &OIDC{
		cfg:      cfg,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		},
		users:  users,
		states: states,
		sink:   sink,
		client: httpClient,
		now:    func() time.Time { return time.Now().UTC() },
	}, nil
}

func withOIDCHTTPClient(ctx context.Context, client *http.Client) context.Context {
	if client == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, client)
}

func sanitizedOIDCError(stage string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("oidc: %s: %w", stage, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("oidc: %s: %w", stage, context.DeadlineExceeded)
	default:
		return fmt.Errorf("oidc: %s failed", stage)
	}
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (o *OIDC) Start(ctx context.Context) (string, error) {
	state := RandomToken(32)
	value := OIDCState{
		Verifier:  RandomToken(32),
		Nonce:     RandomToken(32),
		CreatedAt: o.now().UTC(),
	}
	if err := o.states.Save(ctx, state, value, oidcStateTTL); err != nil {
		return "", err
	}
	return o.oauth.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", pkceS256(value.Verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(value.Nonce),
	), nil
}

type oidcIdentityClaims struct {
	PreferredUsername string
	Email             string
	Name              string
	Groups            []string
}

func (o *OIDC) Complete(ctx context.Context, state, code string) (User, error) {
	value, err := o.states.Take(ctx, state)
	if err != nil {
		return User{}, err
	}
	now := o.now().UTC()
	if value.Verifier == "" || value.Nonce == "" || value.CreatedAt.IsZero() ||
		value.CreatedAt.After(now) || !value.CreatedAt.Add(oidcStateTTL).After(now) {
		return User{}, ErrOIDCStateInvalid
	}
	if code == "" {
		return User{}, errors.New("oidc: authorization code missing")
	}

	ctx = withOIDCHTTPClient(ctx, o.client)
	token, err := o.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", value.Verifier))
	if err != nil {
		return User{}, sanitizedOIDCError("token exchange", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return User{}, errors.New("oidc: token response omitted id token")
	}
	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return User{}, sanitizedOIDCError("id token verification", err)
	}
	if idToken.Nonce != value.Nonce {
		o.recordDenied(ctx, idToken.Subject, "nonce_mismatch")
		return User{}, errors.New("oidc: nonce validation failed")
	}
	if idToken.Issuer == "" || idToken.Issuer != o.cfg.Issuer || strings.TrimSpace(idToken.Subject) == "" {
		return User{}, errors.New("oidc: invalid identity claims")
	}

	claims, err := o.decodeClaims(idToken)
	if err != nil {
		return User{}, errors.New("oidc: invalid identity claims")
	}
	if !slices.Contains(claims.Groups, o.cfg.RequiredGroup) {
		o.recordDenied(ctx, idToken.Subject, "missing_required_group")
		return User{}, ErrNotAuthorised
	}

	username := strings.TrimSpace(claims.PreferredUsername)
	if username == "" {
		username = strings.TrimSpace(claims.Email)
	}
	if username == "" {
		username = idToken.Subject
	}
	user := User{
		ID:          uuid.New(),
		Username:    username,
		DisplayName: claims.Name,
		Provider:    ProviderOIDC,
		OIDCIssuer:  idToken.Issuer,
		OIDCSubject: idToken.Subject,
		IsAdmin:     o.cfg.AdminGroup != "" && slices.Contains(claims.Groups, o.cfg.AdminGroup),
	}
	stored, err := o.users.UpsertOIDC(ctx, user)
	if err != nil {
		return User{}, err
	}
	if stored.Disabled {
		o.recordDenied(ctx, idToken.Subject, "disabled")
		return User{}, ErrNotAuthorised
	}
	o.sink.Record(ctx, audit.Event{
		At:      now,
		Event:   audit.OIDCLogin,
		ActorID: &stored.ID,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"provider": "oidc", "is_admin": stored.IsAdmin},
	})
	return stored, nil
}

func (o *OIDC) decodeClaims(idToken *oidc.IDToken) (oidcIdentityClaims, error) {
	var raw map[string]json.RawMessage
	if err := idToken.Claims(&raw); err != nil {
		return oidcIdentityClaims{}, err
	}
	var claims oidcIdentityClaims
	for name, destination := range map[string]*string{
		"preferred_username": &claims.PreferredUsername,
		"email":              &claims.Email,
		"name":               &claims.Name,
	} {
		value, present := raw[name]
		if !present {
			continue
		}
		if string(value) == "null" || json.Unmarshal(value, destination) != nil {
			return oidcIdentityClaims{}, errors.New("malformed string claim")
		}
	}
	groupValue, present := raw[o.cfg.GroupClaim]
	if !present {
		return claims, nil
	}
	if string(groupValue) == "null" || json.Unmarshal(groupValue, &claims.Groups) != nil {
		return oidcIdentityClaims{}, errors.New("malformed group claim")
	}
	return claims, nil
}

func (o *OIDC) recordDenied(ctx context.Context, subject, reason string) {
	o.sink.Record(ctx, audit.Event{
		At:      o.now().UTC(),
		Event:   audit.OIDCDenied,
		Outcome: audit.OutcomeDenied,
		Details: map[string]any{
			"reason":  reason,
			"issuer":  o.cfg.Issuer,
			"subject": subject,
		},
	})
}
