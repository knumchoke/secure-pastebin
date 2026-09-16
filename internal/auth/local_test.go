package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

type memUsers struct {
	byName   map[string]User
	getErr   error
	touchErr error
	touches  []loginTouch
}

type loginTouch struct {
	id uuid.UUID
	at time.Time
}

var _ UserStore = (*memUsers)(nil)

func (m *memUsers) Create(_ context.Context, u User) error {
	if _, ok := m.byName[u.Username]; ok {
		return ErrUserExists
	}
	m.byName[u.Username] = u
	return nil
}

func (m *memUsers) GetByID(_ context.Context, id uuid.UUID) (User, error) {
	for _, u := range m.byName {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (m *memUsers) GetByUsername(_ context.Context, username string) (User, error) {
	if m.getErr != nil {
		return User{}, m.getErr
	}
	u, ok := m.byName[username]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

func (m *memUsers) GetByOIDC(_ context.Context, issuer, subject string) (User, error) {
	for _, u := range m.byName {
		if u.OIDCIssuer == issuer && u.OIDCSubject == subject {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (m *memUsers) UpsertOIDC(_ context.Context, u User) (User, error) {
	for username, existing := range m.byName {
		if existing.OIDCIssuer == u.OIDCIssuer && existing.OIDCSubject == u.OIDCSubject {
			existing.DisplayName = u.DisplayName
			existing.IsAdmin = u.IsAdmin
			m.byName[username] = existing
			return existing, nil
		}
	}
	m.byName[u.Username] = u
	return u, nil
}

func (m *memUsers) SetPasswordHash(_ context.Context, id uuid.UUID, phc string) error {
	for username, u := range m.byName {
		if u.ID == id {
			u.PasswordHash = phc
			m.byName[username] = u
			return nil
		}
	}
	return ErrUserNotFound
}

func (m *memUsers) SetDisabled(_ context.Context, id uuid.UUID, disabled bool) error {
	for username, u := range m.byName {
		if u.ID == id {
			u.Disabled = disabled
			m.byName[username] = u
			return nil
		}
	}
	return ErrUserNotFound
}

func (m *memUsers) TouchLogin(_ context.Context, id uuid.UUID, at time.Time) error {
	m.touches = append(m.touches, loginTouch{id: id, at: at})
	if m.touchErr != nil {
		return m.touchErr
	}
	for username, u := range m.byName {
		if u.ID == id {
			touchedAt := at
			u.LastLoginAt = &touchedAt
			m.byName[username] = u
			return nil
		}
	}
	return ErrUserNotFound
}

func (m *memUsers) List(context.Context) ([]User, error) {
	users := make([]User, 0, len(m.byName))
	for _, u := range m.byName {
		users = append(users, u)
	}
	return users, nil
}

type memAudit struct{ events []audit.Event }

func (a *memAudit) Record(_ context.Context, e audit.Event) { a.events = append(a.events, e) }

type verifyCall struct {
	phc      string
	password string
}

type fakePasswordHasher struct {
	hashPHC     string
	hashErr     error
	verifyOK    bool
	verifyErr   error
	hashInputs  []string
	verifyCalls []verifyCall
}

var _ PasswordHasher = (*fakePasswordHasher)(nil)

func (h *fakePasswordHasher) Hash(_ context.Context, password string) (string, error) {
	h.hashInputs = append(h.hashInputs, password)
	return h.hashPHC, h.hashErr
}

func (h *fakePasswordHasher) Verify(_ context.Context, phc, password string) (bool, error) {
	h.verifyCalls = append(h.verifyCalls, verifyCall{phc: phc, password: password})
	return h.verifyOK, h.verifyErr
}

func TestLocalAuth_RealArgon2(t *testing.T) {
	ctx := context.Background()
	hasher := NewArgon2Hasher(crypto.NewGate(2, time.Second), fastParams)
	users := &memUsers{byName: map[string]User{}}
	phc, err := hasher.Hash(ctx, "right-password")
	if err != nil {
		t.Fatal(err)
	}
	aliceID := uuid.New()
	users.byName["alice"] = User{ID: aliceID, Username: "alice", Provider: ProviderLocal, PasswordHash: phc}
	users.byName["disabled"] = User{ID: uuid.New(), Username: "disabled", Provider: ProviderLocal, PasswordHash: phc, Disabled: true}
	users.byName["oidc"] = User{ID: uuid.New(), Username: "oidc", Provider: ProviderOIDC}
	users.byName["missing-hash"] = User{ID: uuid.New(), Username: "missing-hash", Provider: ProviderLocal}
	sink := &memAudit{}
	now := time.Date(2026, time.September, 11, 8, 0, 0, 0, time.UTC)
	local, err := NewLocalAuth(users, hasher, sink, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	got, err := local.Authenticate(ctx, "alice", "right-password")
	if err != nil || got.ID != aliceID {
		t.Fatalf("successful login = (%s, %v), want user %s", got.ID, err, aliceID)
	}
	if len(users.touches) != 1 || users.touches[0].id != aliceID || !users.touches[0].at.Equal(now) {
		t.Fatalf("login touches = %+v, want alice at %s", users.touches, now)
	}
	assertSuccessAudit(t, sink.events[len(sink.events)-1], aliceID, now)

	for _, tc := range []struct {
		name     string
		username string
		password string
		reason   string
	}{
		{name: "wrong password", username: "alice", password: "wrong-password", reason: "wrong_password"},
		{name: "unknown user", username: "unknown", password: "guess", reason: "unknown_user"},
		{name: "disabled", username: "disabled", password: "right-password", reason: "disabled"},
		{name: "non-local", username: "oidc", password: "guess", reason: "not_local"},
		{name: "missing hash", username: "missing-hash", password: "guess", reason: "not_local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(sink.events)
			if _, authErr := local.Authenticate(ctx, tc.username, tc.password); !errors.Is(authErr, ErrBadCredentials) {
				t.Fatalf("Authenticate error = %v, want ErrBadCredentials", authErr)
			}
			if len(sink.events) != before+1 {
				t.Fatalf("audit count changed by %d, want 1", len(sink.events)-before)
			}
			assertFailureAudit(t, sink.events[len(sink.events)-1], tc.username, tc.reason, now)
		})
	}
}

func TestLocalAuth_VerifiesExactlyOnceWithExpectedPHC(t *testing.T) {
	storedPHC := "$argon2id$stored-sensitive-value"
	for _, tc := range []struct {
		name    string
		user    *User
		wantPHC string
		ok      bool
	}{
		{name: "known local", user: &User{Username: "alice", Provider: ProviderLocal, PasswordHash: storedPHC}, wantPHC: storedPHC, ok: true},
		{name: "wrong local password", user: &User{Username: "alice", Provider: ProviderLocal, PasswordHash: storedPHC}, wantPHC: storedPHC},
		{name: "disabled local", user: &User{Username: "alice", Provider: ProviderLocal, PasswordHash: storedPHC, Disabled: true}, wantPHC: storedPHC, ok: true},
		{name: "unknown user", wantPHC: "dummy-phc"},
		{name: "non-local", user: &User{Username: "alice", Provider: ProviderOIDC}, wantPHC: "dummy-phc"},
		{name: "missing hash", user: &User{Username: "alice", Provider: ProviderLocal}, wantPHC: "dummy-phc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := &memUsers{byName: map[string]User{}}
			if tc.user != nil {
				tc.user.ID = uuid.New()
				users.byName[tc.user.Username] = *tc.user
			}
			hasher := &fakePasswordHasher{hashPHC: "dummy-phc", verifyOK: tc.ok}
			local, err := NewLocalAuth(users, hasher, &memAudit{}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = local.Authenticate(context.Background(), "alice", "candidate-password")
			if len(hasher.verifyCalls) != 1 {
				t.Fatalf("Verify calls = %d, want 1", len(hasher.verifyCalls))
			}
			if call := hasher.verifyCalls[0]; call.phc != tc.wantPHC || call.password != "candidate-password" {
				t.Fatal("Verify did not receive the expected PHC and supplied password")
			}
		})
	}
}

func TestLocalAuth_PropagatesVerificationErrorsUniformly(t *testing.T) {
	busyErr := paste.ErrKDFBusy
	otherErr := errors.New("verify failed")
	canceledErr := context.Canceled
	for _, verifyErr := range []error{busyErr, canceledErr, otherErr} {
		for _, tc := range []struct {
			name string
			user *User
		}{
			{name: "known local", user: &User{Username: "alice", Provider: ProviderLocal, PasswordHash: "stored-phc"}},
			{name: "disabled local", user: &User{Username: "alice", Provider: ProviderLocal, PasswordHash: "stored-phc", Disabled: true}},
			{name: "unknown user"},
			{name: "non-local", user: &User{Username: "alice", Provider: ProviderOIDC}},
			{name: "missing hash", user: &User{Username: "alice", Provider: ProviderLocal}},
		} {
			t.Run(tc.name+"/"+verifyErr.Error(), func(t *testing.T) {
				users := &memUsers{byName: map[string]User{}}
				if tc.user != nil {
					tc.user.ID = uuid.New()
					users.byName[tc.user.Username] = *tc.user
				}
				hasher := &fakePasswordHasher{hashPHC: "dummy-phc", verifyErr: verifyErr}
				sink := &memAudit{}
				local, err := NewLocalAuth(users, hasher, sink, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				_, authErr := local.Authenticate(context.Background(), "alice", "candidate-password")
				if !errors.Is(authErr, verifyErr) {
					t.Fatalf("Authenticate error = %v, want %v", authErr, verifyErr)
				}
				if len(hasher.verifyCalls) != 1 {
					t.Fatalf("Verify calls = %d, want 1", len(hasher.verifyCalls))
				}
				if len(sink.events) != 0 {
					t.Fatalf("audit events = %d, want none for operational error", len(sink.events))
				}
			})
		}
	}
}

func TestNewLocalAuth_ConstructorHashError(t *testing.T) {
	wantErr := errors.New("hash failed")
	hasher := &fakePasswordHasher{hashErr: wantErr}
	local, err := NewLocalAuth(&memUsers{byName: map[string]User{}}, hasher, &memAudit{}, time.Now)
	if local != nil || !errors.Is(err, wantErr) {
		t.Fatalf("NewLocalAuth returned instance=%t and expected error=%t", local != nil, errors.Is(err, wantErr))
	}
	if len(hasher.hashInputs) != 1 || len(hasher.hashInputs[0]) != 32 {
		t.Fatal("dummy hash input was not one 24-byte base64url token")
	}
}

func TestLocalAuth_PropagatesStoreErrorWithoutVerificationOrAudit(t *testing.T) {
	wantErr := errors.New("store unavailable")
	users := &memUsers{byName: map[string]User{}, getErr: wantErr}
	hasher := &fakePasswordHasher{hashPHC: "dummy-phc"}
	sink := &memAudit{}
	local, err := NewLocalAuth(users, hasher, sink, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, authErr := local.Authenticate(context.Background(), "alice", "candidate-password")
	if !errors.Is(authErr, wantErr) {
		t.Fatalf("Authenticate error = %v, want %v", authErr, wantErr)
	}
	if len(hasher.verifyCalls) != 0 || len(sink.events) != 0 {
		t.Fatalf("operational store error caused %d verify calls and %d audit events", len(hasher.verifyCalls), len(sink.events))
	}
}

func TestLocalAuth_SuccessIgnoresTouchErrorAndUsesUTCDefaultClock(t *testing.T) {
	uid := uuid.New()
	users := &memUsers{
		byName:   map[string]User{"alice": {ID: uid, Username: "alice", Provider: ProviderLocal, PasswordHash: "stored-phc"}},
		touchErr: errors.New("touch failed"),
	}
	hasher := &fakePasswordHasher{hashPHC: "dummy-phc", verifyOK: true}
	sink := &memAudit{}
	local, err := NewLocalAuth(users, hasher, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	got, err := local.Authenticate(context.Background(), "alice", "candidate-password")
	after := time.Now().UTC()
	if err != nil || got.ID != uid {
		t.Fatalf("Authenticate = (%s, %v), want user %s", got.ID, err, uid)
	}
	if len(users.touches) != 1 || len(sink.events) != 1 {
		t.Fatalf("touches/events = %d/%d, want 1/1", len(users.touches), len(sink.events))
	}
	touchedAt := users.touches[0].at
	if touchedAt.Location() != time.UTC || touchedAt.Before(before) || touchedAt.After(after) {
		t.Fatalf("touch time = %s (%s), want UTC between %s and %s", touchedAt, touchedAt.Location(), before, after)
	}
	assertSuccessAudit(t, sink.events[0], uid, touchedAt)
}

func assertSuccessAudit(t *testing.T, event audit.Event, userID uuid.UUID, at time.Time) {
	t.Helper()
	if event.Event != audit.LoginSuccess || event.Outcome != audit.OutcomeSuccess || event.ActorID == nil || *event.ActorID != userID || !event.At.Equal(at) {
		t.Fatal("success audit metadata did not match")
	}
	if len(event.Details) != 1 || event.Details["provider"] != "local" {
		t.Fatal("success audit details did not contain only the provider")
	}
}

func assertFailureAudit(t *testing.T, event audit.Event, username, reason string, at time.Time) {
	t.Helper()
	if event.Event != audit.LoginFailure || event.Outcome != audit.OutcomeFailure || event.ActorID != nil || !event.At.Equal(at) {
		t.Fatal("failure audit metadata did not match")
	}
	want := map[string]any{"username": username, "reason": reason, "provider": "local"}
	if len(event.Details) != len(want) {
		t.Fatal("failure audit details did not contain exactly username, reason, and provider")
	}
	for key, value := range want {
		if event.Details[key] != value {
			t.Fatalf("failure audit detail %q did not match", key)
		}
	}
	for _, forbidden := range []string{"right-password", "wrong-password", "guess", "$argon2id$", "dummy-phc"} {
		for _, value := range event.Details {
			if value == forbidden {
				t.Fatal("failure audit leaked credential material")
			}
		}
	}
}
