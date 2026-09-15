package httpserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/logging"
)

type middleware func(http.Handler) http.Handler

// chain applies middlewares so that the first one listed is outermost.
func chain(h http.Handler, ms ...middleware) http.Handler {
	for i := len(ms) - 1; i >= 0; i-- {
		h = ms[i](h)
	}
	return h
}

type ipKey struct{}

func ipFrom(ctx context.Context) string {
	v, _ := ctx.Value(ipKey{}).(string)
	return v
}

func recoverer(log *slog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.ErrorContext(r.Context(), "panic", "panic", rec, "path", r.URL.Path, "request_id", logging.RequestID(r.Context()))
					writeError(w, http.StatusInternalServerError, "internal", "internal error", nil)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func requestID() middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := auth.RandomToken(12)
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(logging.WithRequestID(r.Context(), id)))
		})
	}
}

// clientIP resolves the caller address (spec §12 TRUSTED_PROXY_CIDRS) and
// attaches it for rate limiting and audit.
func clientIP(trusted []netip.Prefix) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := host
			if peer, err := netip.ParseAddr(host); err == nil {
				for _, p := range trusted {
					if p.Contains(peer) {
						if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
							parts := strings.Split(xff, ",")
							if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
								ip = last
							}
						}
						break
					}
				}
			}
			ctx := context.WithValue(r.Context(), ipKey{}, ip)
			ctx = audit.WithRequestInfo(ctx, ip, r.UserAgent())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func securityHeaders(hsts bool) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			h.Set("Content-Security-Policy", csp)
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func accessLog(log *slog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: 200}
			start := time.Now()
			next.ServeHTTP(sw, r)
			log.InfoContext(r.Context(), "http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
				"ms", time.Since(start).Milliseconds(), "ip", ipFrom(r.Context()), "request_id", logging.RequestID(r.Context()))
		})
	}
}

func maxBody(n int64) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}
