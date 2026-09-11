package postgres

import (
	"context"
	"testing"
)

func TestIntegration_MigrateIsIdempotent(t *testing.T) {
	pool := StartTestDB(t)
	ctx := context.Background()
	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "0001_init.sql" {
		t.Fatalf("applied = %v", applied)
	}
	applied, err = Migrate(ctx, pool)
	if err != nil || len(applied) != 0 {
		t.Fatalf("second run: %v %v", applied, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('users','pastes','audit_events')`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("tables = %d, %v", n, err)
	}
}
