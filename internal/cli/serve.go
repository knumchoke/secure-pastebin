package cli

import (
	"context"
	"fmt"
	"net/http"

	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/httpserver"
	"github.com/knumchoke/secure-pastebin/internal/logging"
	"github.com/knumchoke/secure-pastebin/internal/store/postgres"
)

func init() { Register("serve", runServe) }

func runServe(ctx context.Context, env Env, _ []string) int {
	cfg, err := config.Load(env.Getenv)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	log := logging.New(env.Stderr, cfg.LogLevel)
	log.Info("config loaded", "config", cfg.Redacted())
	log.Info("recommended redis maxmemory", "bytes", cfg.RecommendedRedisMaxMemory(), "human", config.FormatSize(cfg.RecommendedRedisMaxMemory()))

	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("postgres", "err", err)
		return 1
	}
	defer pool.Close()

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", httpserver.HealthHandler())
	mux.Handle("GET /readyz", httpserver.ReadyHandler(map[string]func(context.Context) error{
		"postgres": pool.Ping,
	}))
	if err := httpserver.Serve(ctx, log, cfg, mux); err != nil {
		log.Error("server", "err", err)
		return 1
	}
	return 0
}
