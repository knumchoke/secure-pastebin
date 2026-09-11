package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// StartTestDB starts a throwaway Postgres 16 container and returns a pool.
// Skipped unless PASTEBIN_INTEGRATION=1.
func StartTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("PASTEBIN_INTEGRATION") != "1" {
		t.Skip("set PASTEBIN_INTEGRATION=1 to run")
	}
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("pastebin"), tcpostgres.WithUsername("pastebin"), tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	url, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
