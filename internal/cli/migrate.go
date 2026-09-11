package cli

import (
	"context"
	"fmt"

	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/logging"
	"github.com/knumchoke/secure-pastebin/internal/store/postgres"
)

func init() { Register("migrate", runMigrate) }

func runMigrate(ctx context.Context, env Env, _ []string) int {
	cfg, err := config.Load(env.Getenv)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	log := logging.New(env.Stderr, cfg.LogLevel)
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("connect", "err", err)
		return 1
	}
	defer pool.Close()
	applied, err := postgres.Migrate(ctx, pool)
	if err != nil {
		log.Error("migrate failed", "err", err, "applied", applied)
		return 1
	}
	log.Info("migrations applied", "count", len(applied), "names", applied)
	return 0
}
