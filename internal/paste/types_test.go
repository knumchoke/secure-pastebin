package paste

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPasteMeta_Status(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	base := PasteMeta{ID: uuid.New(), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if s := base.Status(now); s != StatusActive {
		t.Errorf("active: got %s", s)
	}
	exp := base
	exp.ExpiresAt = now.Add(-time.Second)
	if s := exp.Status(now); s != StatusExpired {
		t.Errorf("expired: got %s", s)
	}
	del := base
	d := now.Add(-time.Second)
	del.DeletedAt = &d
	if s := del.Status(now); s != StatusDeleted {
		t.Errorf("deleted: got %s", s)
	}
	// deleted wins over expired
	del.ExpiresAt = now.Add(-time.Hour)
	if s := del.Status(now); s != StatusDeleted {
		t.Errorf("deleted+expired: got %s", s)
	}
}

func TestErrTooLarge_Message(t *testing.T) {
	err := &ErrTooLarge{Limit: 10, Actual: 11}
	if err.Error() == "" {
		t.Fatal("empty message")
	}
}
