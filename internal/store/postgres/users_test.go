package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

func TestIntegration_UserStore_LocalLifecycle(t *testing.T) {
	pool := migratedDB(t)
	store := NewUserStore(pool)
	ctx := context.Background()

	initialHash := strings.Join([]string{"$argon2id$", "v=19$", "fixed-initial"}, "")
	alice := auth.User{
		ID:           uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		Username:     "alice",
		DisplayName:  "Alice Example",
		Provider:     auth.ProviderLocal,
		PasswordHash: initialHash,
		IsAdmin:      true,
	}
	if err := store.Create(ctx, alice); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if err := store.Create(ctx, alice); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("duplicate create error = %v, want ErrUserExists", err)
	}

	got, err := store.GetByUsername(ctx, alice.Username)
	if err != nil {
		t.Fatalf("get by username: %v", err)
	}
	if got.ID != alice.ID || got.Username != alice.Username || got.DisplayName != alice.DisplayName ||
		got.Provider != auth.ProviderLocal || got.OIDCIssuer != "" || got.OIDCSubject != "" ||
		got.PasswordHash != alice.PasswordHash || !got.IsAdmin || got.Disabled || got.CreatedAt.IsZero() || got.LastLoginAt != nil {
		t.Fatal("alice fields did not round trip")
	}
	createdAt := got.CreatedAt

	byID, err := store.GetByID(ctx, alice.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if byID != got {
		t.Fatal("get by id did not return the created user")
	}
	if _, err := store.GetByID(ctx, uuid.MustParse("00000000-0000-4000-8000-000000000099")); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("missing id error = %v, want ErrUserNotFound", err)
	}
	if _, err := store.GetByUsername(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("missing username error = %v, want ErrUserNotFound", err)
	}

	updatedHash := strings.Join([]string{"$argon2id$", "v=19$", "fixed-updated"}, "")
	if err := store.SetPasswordHash(ctx, alice.ID, updatedHash); err != nil {
		t.Fatalf("set password hash: %v", err)
	}
	if err := store.SetDisabled(ctx, alice.ID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if disabled, err := store.GetByID(ctx, alice.ID); err != nil || !disabled.Disabled {
		t.Fatalf("disabled state was not stored: %v", err)
	}
	if err := store.SetDisabled(ctx, alice.ID, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	loginAt := time.Date(2026, time.September, 15, 9, 10, 11, 123456000, time.UTC)
	if err := store.TouchLogin(ctx, alice.ID, loginAt); err != nil {
		t.Fatalf("touch login: %v", err)
	}
	got, err = store.GetByID(ctx, alice.ID)
	if err != nil {
		t.Fatalf("get updated alice: %v", err)
	}
	if got.PasswordHash != updatedHash || got.Disabled || got.LastLoginAt == nil || !got.LastLoginAt.Equal(loginAt) || !got.CreatedAt.Equal(createdAt) {
		t.Fatal("local user updates were not stored")
	}

	bob := auth.User{
		ID:       uuid.MustParse("00000000-0000-4000-8000-000000000002"),
		Username: "bob",
		Provider: auth.ProviderLocal,
	}
	if err := store.Create(ctx, bob); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].Username != "alice" || list[1].Username != "bob" {
		t.Fatalf("list length/order incorrect: length=%d", len(list))
	}
}

func TestIntegration_UserStore_OIDCUpsert(t *testing.T) {
	pool := migratedDB(t)
	store := NewUserStore(pool)
	ctx := context.Background()

	firstInput := auth.User{
		ID:          uuid.MustParse("00000000-0000-4000-8000-000000000010"),
		Username:    "oidc-user",
		DisplayName: "First Name",
		Provider:    auth.ProviderLocal,
		OIDCIssuer:  "https://idp.example.test/realms/main",
		OIDCSubject: "subject-10",
		IsAdmin:     true,
		Disabled:    true,
	}
	first, err := store.UpsertOIDC(ctx, firstInput)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.ID != firstInput.ID || first.Username != firstInput.Username || first.DisplayName != firstInput.DisplayName ||
		first.Provider != auth.ProviderOIDC || first.OIDCIssuer != firstInput.OIDCIssuer || first.OIDCSubject != firstInput.OIDCSubject ||
		first.PasswordHash != "" || !first.IsAdmin || first.Disabled || first.CreatedAt.IsZero() || first.LastLoginAt == nil {
		t.Fatal("first OIDC upsert returned incorrect fields")
	}
	oldLogin := time.Date(2000, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := store.TouchLogin(ctx, first.ID, oldLogin); err != nil {
		t.Fatalf("seed old OIDC login: %v", err)
	}
	if err := store.SetDisabled(ctx, first.ID, true); err != nil {
		t.Fatalf("disable oidc user: %v", err)
	}
	preservedHash := strings.Join([]string{"$argon2id$", "v=19$", "fixed-preserved"}, "")
	if err := store.SetPasswordHash(ctx, first.ID, preservedHash); err != nil {
		t.Fatalf("seed OIDC password hash: %v", err)
	}

	secondInput := firstInput
	secondInput.ID = uuid.MustParse("00000000-0000-4000-8000-000000000011")
	secondInput.Username = "replacement-name"
	secondInput.DisplayName = "Updated Name"
	secondInput.IsAdmin = false
	second, err := store.UpsertOIDC(ctx, secondInput)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.ID != first.ID || second.Username != first.Username || second.DisplayName != secondInput.DisplayName ||
		second.Provider != auth.ProviderOIDC || second.PasswordHash != preservedHash || second.IsAdmin || !second.Disabled ||
		second.CreatedAt != first.CreatedAt || second.LastLoginAt == nil || !second.LastLoginAt.After(oldLogin) {
		t.Fatal("second OIDC upsert did not preserve identity and disabled state")
	}

	thirdInput := secondInput
	thirdInput.DisplayName = "Admin Again"
	thirdInput.IsAdmin = true
	third, err := store.UpsertOIDC(ctx, thirdInput)
	if err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	if !third.IsAdmin || third.DisplayName != thirdInput.DisplayName || !third.Disabled || third.ID != first.ID || third.Username != first.Username {
		t.Fatal("third OIDC upsert did not restore admin status")
	}

	byOIDC, err := store.GetByOIDC(ctx, first.OIDCIssuer, first.OIDCSubject)
	if err != nil {
		t.Fatalf("get by oidc: %v", err)
	}
	if byOIDC.ID != first.ID {
		t.Fatalf("get by oidc id = %s, want %s", byOIDC.ID, first.ID)
	}
	if _, err := store.GetByOIDC(ctx, first.OIDCIssuer, "missing-subject"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("missing oidc error = %v, want ErrUserNotFound", err)
	}

	local := auth.User{
		ID:       uuid.MustParse("00000000-0000-4000-8000-000000000020"),
		Username: "already-taken",
		Provider: auth.ProviderLocal,
	}
	if err := store.Create(ctx, local); err != nil {
		t.Fatalf("create collision user: %v", err)
	}
	collision := auth.User{
		ID:          uuid.MustParse("00000000-0000-4000-8000-000000000021"),
		Username:    local.Username,
		DisplayName: "Collision",
		OIDCIssuer:  "https://idp.example.test/realms/other",
		OIDCSubject: "subject-21",
	}
	if _, err := store.UpsertOIDC(ctx, collision); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("username collision error = %v, want ErrUserExists", err)
	}
}
