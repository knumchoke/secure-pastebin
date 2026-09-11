package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/config"
)

// Serve runs h until ctx is cancelled, then shuts down gracefully (≤10 s).
func Serve(ctx context.Context, log *slog.Logger, cfg *config.Config, h http.Handler) error {
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	useTLS := cfg.TLSCertFile != ""
	if useTLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		log.Warn("TLS not configured: serving plain HTTP; only acceptable behind a TLS-terminating proxy")
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "tls", useTLS)
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Info("shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}
