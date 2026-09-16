package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
)

type cliMemUsers struct {
	byName      map[string]auth.User
	createErr   error
	getErr      error
	passwordErr error
	disabledErr error
	listErr     error
}

func (m *cliMemUsers) Create(_ context.Context, user auth.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	if _, exists := m.byName[user.Username]; exists {
		return auth.ErrUserExists
	}
	m.byName[user.Username] = user
	return nil
}

func (m *cliMemUsers) GetByID(context.Context, uuid.UUID) (auth.User, error) {
	return auth.User{}, auth.ErrUserNotFound
}

func (m *cliMemUsers) GetByUsername(_ context.Context, username string) (auth.User, error) {
	if m.getErr != nil {
		return auth.User{}, m.getErr
	}
	user, ok := m.byName[username]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return user, nil
}

func (m *cliMemUsers) GetByOIDC(context.Context, string, string) (auth.User, error) {
	return auth.User{}, auth.ErrUserNotFound
}

func (m *cliMemUsers) UpsertOIDC(_ context.Context, user auth.User) (auth.User, error) {
	return user, nil
}

func (m *cliMemUsers) SetPasswordHash(_ context.Context, id uuid.UUID, phc string) error {
	if m.passwordErr != nil {
		return m.passwordErr
	}
	for username, user := range m.byName {
		if user.ID == id {
			user.PasswordHash = phc
			m.byName[username] = user
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (m *cliMemUsers) SetDisabled(_ context.Context, id uuid.UUID, disabled bool) error {
	if m.disabledErr != nil {
		return m.disabledErr
	}
	for username, user := range m.byName {
		if user.ID == id {
			user.Disabled = disabled
			m.byName[username] = user
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (m *cliMemUsers) TouchLogin(context.Context, uuid.UUID, time.Time) error { return nil }

func (m *cliMemUsers) List(context.Context) ([]auth.User, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	users := make([]auth.User, 0, len(m.byName))
	for _, user := range m.byName {
		users = append(users, user)
	}
	return users, nil
}

type cliMemSink struct{ events []audit.Event }

func (s *cliMemSink) Record(_ context.Context, event audit.Event) {
	s.events = append(s.events, event)
}

type cliFailHasher struct{ err error }

func (h cliFailHasher) Hash(context.Context, string) (string, error) { return "", h.err }
func (h cliFailHasher) Verify(context.Context, string, string) (bool, error) {
	return false, h.err
}

func newUserTestDeps() (userDeps, *cliMemUsers, *cliMemSink, auth.PasswordHasher) {
	users := &cliMemUsers{byName: map[string]auth.User{}}
	sink := &cliMemSink{}
	hasher := auth.NewArgon2Hasher(
		crypto.NewGate(1, time.Second),
		crypto.Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1},
	)
	return userDeps{users: users, hasher: hasher, sink: sink}, users, sink, hasher
}

func runUserTest(t *testing.T, deps userDeps, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runUserWith(context.Background(), Env{
		Getenv: func(string) string { return "" },
		Stdin:  strings.NewReader(stdin),
		Stdout: &stdout,
		Stderr: &stderr,
	}, args, deps)
	return code, stdout.String(), stderr.String()
}

func TestUserCommandRegistered(t *testing.T) {
	if registry["user"] == nil {
		t.Fatal("user command was not registered")
	}
}

func TestUserCreateHashesPasswordAndAudits(t *testing.T) {
	deps, users, sink, hasher := newUserTestDeps()
	const password = "long-enough password"
	code, stdout, stderr := runUserTest(t, deps, password+"\n", "create", "--username", "alice", "--admin", "--display-name", "Alice")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	user := users.byName["alice"]
	if user.ID == uuid.Nil || user.Provider != auth.ProviderLocal || user.DisplayName != "Alice" || !user.IsAdmin || !strings.HasPrefix(user.PasswordHash, "$argon2id$") {
		t.Fatalf("created user = %+v", user)
	}
	ok, err := hasher.Verify(context.Background(), user.PasswordHash, password)
	if err != nil || !ok {
		t.Fatalf("created password verification: ok=%v err=%v", ok, err)
	}
	if len(sink.events) != 1 || sink.events[0].Event != audit.UserCreated || sink.events[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("audit events = %+v", sink.events)
	}
	details := sink.events[0].Details
	if details["username"] != "alice" || details["admin"] != true || details["via"] != "cli" {
		t.Fatalf("audit details = %#v", details)
	}
	if strings.Contains(stdout+stderr, password) {
		t.Fatal("password was echoed")
	}
}

func TestUserCreatePreservesPasswordSpacesAndAcceptsEOF(t *testing.T) {
	deps, users, _, hasher := newUserTestDeps()
	const password = "  enough password spaces  "
	code, _, stderr := runUserTest(t, deps, password, "create", "--username", "spaced")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	stored := users.byName["spaced"].PasswordHash
	ok, err := hasher.Verify(context.Background(), stored, password)
	if err != nil || !ok {
		t.Fatalf("exact password verification: ok=%v err=%v", ok, err)
	}
	ok, err = hasher.Verify(context.Background(), stored, strings.TrimSpace(password))
	if err != nil || ok {
		t.Fatalf("trimmed password verification: ok=%v err=%v", ok, err)
	}
}

func TestUserCreateValidationAndDuplicate(t *testing.T) {
	deps, _, _, _ := newUserTestDeps()
	if code, _, _ := runUserTest(t, deps, "long-enough-password\n", "create"); code != 2 {
		t.Fatalf("missing username code=%d, want 2", code)
	}
	if code, _, stderr := runUserTest(t, deps, "too short\n", "create", "--username", "bob"); code != 1 || !strings.Contains(stderr, "at least 12") {
		t.Fatalf("short password code=%d stderr=%q", code, stderr)
	}
	invalidUTF8 := string([]byte{'l', 'o', 'n', 'g', '-', 'e', 'n', 'o', 'u', 'g', 'h', '-', 0xff, '\n'})
	if code, _, stderr := runUserTest(t, deps, invalidUTF8, "create", "--username", "bob"); code != 1 || !strings.Contains(stderr, "valid UTF-8") {
		t.Fatalf("invalid UTF-8 code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := runUserTest(t, deps, "long-enough-password\n", "create", "--username", "bob"); code != 0 {
		t.Fatalf("first create code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := runUserTest(t, deps, "another-long-password\n", "create", "--username", "bob"); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate code=%d stderr=%q", code, stderr)
	}
}

func TestUserSetPasswordUsesRealArgon2AndRejectsOIDC(t *testing.T) {
	deps, users, _, hasher := newUserTestDeps()
	if code, _, stderr := runUserTest(t, deps, "first-long-password\n", "create", "--username", "carol"); code != 0 {
		t.Fatalf("create code=%d stderr=%q", code, stderr)
	}
	oldHash := users.byName["carol"].PasswordHash
	if code, _, stderr := runUserTest(t, deps, "second-long-password\n", "set-password", "--username", "carol"); code != 0 {
		t.Fatalf("set-password code=%d stderr=%q", code, stderr)
	}
	newHash := users.byName["carol"].PasswordHash
	if newHash == oldHash {
		t.Fatal("password hash did not change")
	}
	if ok, err := hasher.Verify(context.Background(), newHash, "second-long-password"); err != nil || !ok {
		t.Fatalf("new password verification: ok=%v err=%v", ok, err)
	}
	if ok, err := hasher.Verify(context.Background(), newHash, "first-long-password"); err != nil || ok {
		t.Fatalf("old password verification: ok=%v err=%v", ok, err)
	}

	users.byName["oidc-user"] = auth.User{ID: uuid.New(), Username: "oidc-user", Provider: auth.ProviderOIDC}
	if code, _, stderr := runUserTest(t, deps, "must-not-be-read-password\n", "set-password", "--username", "oidc-user"); code != 1 || !strings.Contains(stderr, "local users") {
		t.Fatalf("OIDC reset code=%d stderr=%q", code, stderr)
	}
	if users.byName["oidc-user"].PasswordHash != "" {
		t.Fatal("OIDC user received a password hash")
	}
}

func TestUserDisableEnableListAndAudit(t *testing.T) {
	deps, users, sink, hasher := newUserTestDeps()
	passwordHash, err := hasher.Hash(context.Background(), "list-test-password")
	if err != nil {
		t.Fatalf("hash list fixture password: %v", err)
	}
	lastLogin := time.Date(2026, 9, 16, 3, 4, 5, 0, time.FixedZone("test", 7*60*60))
	users.byName["dana"] = auth.User{
		ID:           uuid.New(),
		Username:     "dana",
		Provider:     auth.ProviderLocal,
		PasswordHash: passwordHash,
		LastLoginAt:  &lastLogin,
	}
	if code, _, stderr := runUserTest(t, deps, "", "disable", "--username", "dana"); code != 0 || !users.byName["dana"].Disabled {
		t.Fatalf("disable code=%d stderr=%q user=%+v", code, stderr, users.byName["dana"])
	}
	if len(sink.events) != 1 || sink.events[0].Event != audit.UserDisabled || sink.events[0].Details["via"] != "cli" {
		t.Fatalf("disable audit = %+v", sink.events)
	}
	if code, _, stderr := runUserTest(t, deps, "", "enable", "--username", "dana"); code != 0 || users.byName["dana"].Disabled {
		t.Fatalf("enable code=%d stderr=%q user=%+v", code, stderr, users.byName["dana"])
	}
	if len(sink.events) != 1 {
		t.Fatalf("enable unexpectedly audited as disable: %+v", sink.events)
	}
	code, stdout, stderr := runUserTest(t, deps, "", "list")
	if code != 0 || !strings.Contains(stdout, "dana") || !strings.Contains(stdout, "local") || !strings.Contains(stdout, "2026-09-15T20:04:05Z") {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, passwordHash) || strings.Contains(stdout+stderr, "$argon2id$") {
		t.Fatalf("list exposed password hash: stdout=%q stderr=%q", stdout, stderr)
	}
	if code, _, stderr := runUserTest(t, deps, "", "disable", "--username", "missing"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Fatalf("unknown user code=%d stderr=%q", code, stderr)
	}
}

func TestUserRejectsBadArgumentsWithoutEchoingThem(t *testing.T) {
	deps, _, _, _ := newUserTestDeps()
	const suppliedSecret = "argument-secret-password"
	tests := [][]string{
		{},
		{"unknown"},
		{"create", "--username", "alice", suppliedSecret},
		{"create", "--username", "alice", "--password", suppliedSecret},
		{"disable", "--username", "alice", "--admin"},
		{"list", "--username", "alice"},
		{"list", "positional"},
	}
	for _, args := range tests {
		code, stdout, stderr := runUserTest(t, deps, "unused-long-password\n", args...)
		if code != 2 {
			t.Errorf("args=%v code=%d, want 2", args, code)
		}
		if strings.Contains(stdout+stderr, suppliedSecret) {
			t.Errorf("args=%v echoed supplied password: stdout=%q stderr=%q", args, stdout, stderr)
		}
	}
}

func TestRunUserRejectsBadArgumentsBeforeLoadingConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runUser(context.Background(), Env{
		Getenv: func(string) string { return "" },
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, []string{"create", "--password", "argument-secret-password"})
	if code != 2 {
		t.Fatalf("code=%d, want 2; stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "argument-secret-password") || strings.Contains(stderr.String(), "config:") {
		t.Fatalf("unsafe or config-first parse error: %q", stderr.String())
	}
}

func TestUserBackendFailuresAreOperational(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		setup func(*userDeps, *cliMemUsers)
		want  string
	}{
		{name: "hash", args: []string{"create", "--username", "alice"}, stdin: "long-enough-password\n", setup: func(deps *userDeps, _ *cliMemUsers) {
			deps.hasher = cliFailHasher{err: errors.New("KDF unavailable")}
		}, want: "KDF unavailable"},
		{name: "create", args: []string{"create", "--username", "alice"}, stdin: "long-enough-password\n", setup: func(_ *userDeps, users *cliMemUsers) {
			users.createErr = errors.New("create backend unavailable")
		}, want: "create backend unavailable"},
		{name: "lookup", args: []string{"disable", "--username", "alice"}, setup: func(_ *userDeps, users *cliMemUsers) {
			users.getErr = errors.New("lookup backend unavailable")
		}, want: "lookup backend unavailable"},
		{name: "set password", args: []string{"set-password", "--username", "alice"}, stdin: "long-enough-password\n", setup: func(_ *userDeps, users *cliMemUsers) {
			users.byName["alice"] = auth.User{ID: uuid.New(), Username: "alice", Provider: auth.ProviderLocal}
			users.passwordErr = errors.New("password backend unavailable")
		}, want: "password backend unavailable"},
		{name: "set disabled", args: []string{"disable", "--username", "alice"}, setup: func(_ *userDeps, users *cliMemUsers) {
			users.byName["alice"] = auth.User{ID: uuid.New(), Username: "alice", Provider: auth.ProviderLocal}
			users.disabledErr = errors.New("disabled backend unavailable")
		}, want: "disabled backend unavailable"},
		{name: "list", args: []string{"list"}, setup: func(_ *userDeps, users *cliMemUsers) {
			users.listErr = errors.New("list backend unavailable")
		}, want: "list backend unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps, users, sink, _ := newUserTestDeps()
			test.setup(&deps, users)
			code, stdout, stderr := runUserTest(t, deps, test.stdin, test.args...)
			if code != 1 || !strings.Contains(stderr, test.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if len(sink.events) != 0 {
				t.Fatalf("failure emitted success audit: %+v", sink.events)
			}
			if test.stdin != "" && strings.Contains(stdout+stderr, test.stdin) {
				t.Fatalf("password input was echoed: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestUserPasswordInputRequired(t *testing.T) {
	deps, _, _, _ := newUserTestDeps()
	code, _, stderr := runUserTest(t, deps, "", "create", "--username", "alice")
	if code != 1 || !strings.Contains(stderr, "no password on stdin") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}
