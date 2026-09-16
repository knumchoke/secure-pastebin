package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/logging"
	"github.com/knumchoke/secure-pastebin/internal/store/postgres"
)

func init() { Register("user", runUser) }

type userDeps struct {
	users  auth.UserStore
	hasher auth.PasswordHasher
	sink   audit.Sink
}

const minLocalPasswordLen = 12

func runUser(ctx context.Context, env Env, args []string) int {
	if len(args) == 0 {
		return userUsage(env)
	}
	if _, ok := parseUserOptions(env, args[0], args[1:]); !ok {
		if !isUserSubcommand(args[0]) {
			return userUsage(env)
		}
		return 2
	}

	cfg, err := config.Load(env.Getenv)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}

	log := logging.New(env.Stderr, cfg.LogLevel)
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	defer pool.Close()

	sinks := audit.Multi{audit.NewLogSink(log)}
	if cfg.AuditDBEnabled {
		sinks = append(sinks, postgres.NewAuditStore(pool, log))
	}
	gate := crypto.NewGate(cfg.Argon2.MaxConcurrent, cfg.Argon2.QueueTimeout)
	return runUserWith(ctx, env, args, userDeps{
		users:  postgres.NewUserStore(pool),
		hasher: auth.NewArgon2Hasher(gate, crypto.ParamsFromConfig(cfg.Argon2)),
		sink:   sinks,
	})
}

func userUsage(env Env) int {
	fmt.Fprintln(env.Stderr, "usage: pastebin user <create|set-password|disable|enable|list> [flags]")
	fmt.Fprintln(env.Stderr, "  create --username U [--admin] [--display-name N]")
	fmt.Fprintln(env.Stderr, "  set-password --username U")
	fmt.Fprintln(env.Stderr, "  disable --username U")
	fmt.Fprintln(env.Stderr, "  enable --username U")
	fmt.Fprintln(env.Stderr, "  list")
	fmt.Fprintln(env.Stderr, "passwords are read from stdin; never pass them as arguments")
	return 2
}

func invalidUserArgs(env Env, subcommand string) int {
	fmt.Fprintf(env.Stderr, "invalid arguments for user %s\n", subcommand)
	return userUsage(env)
}

type userOptions struct {
	username    string
	displayName string
	admin       bool
}

func parseUserOptions(env Env, subcommand string, args []string) (userOptions, bool) {
	var opts userOptions
	fs := flag.NewFlagSet("user "+subcommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	switch subcommand {
	case "create":
		fs.StringVar(&opts.username, "username", "", "username")
		fs.StringVar(&opts.displayName, "display-name", "", "display name")
		fs.BoolVar(&opts.admin, "admin", false, "grant admin")
	case "set-password", "disable", "enable":
		fs.StringVar(&opts.username, "username", "", "username")
	case "list":
	default:
		return userOptions{}, false
	}

	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		invalidUserArgs(env, subcommand)
		return userOptions{}, false
	}
	if subcommand != "list" && opts.username == "" {
		invalidUserArgs(env, subcommand)
		return userOptions{}, false
	}
	return opts, true
}

func isUserSubcommand(name string) bool {
	switch name {
	case "create", "set-password", "disable", "enable", "list":
		return true
	default:
		return false
	}
}

// readUserPassword disables terminal echo and asks for confirmation on a TTY.
// For piped input it reads exactly one line so automation only supplies one copy.
func readUserPassword(env Env) ([]byte, error) {
	if file, ok := env.Stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(env.Stderr, "Password: ")
		first, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(env.Stderr)
		if err != nil {
			crypto.Zero(first)
			return nil, fmt.Errorf("read password: %w", err)
		}

		fmt.Fprint(env.Stderr, "Confirm password: ")
		second, confirmErr := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(env.Stderr)
		defer crypto.Zero(second)
		if confirmErr != nil {
			crypto.Zero(first)
			return nil, fmt.Errorf("read password confirmation: %w", confirmErr)
		}
		if string(first) != string(second) {
			crypto.Zero(first)
			return nil, errors.New("passwords do not match")
		}
		return first, nil
	}

	if env.Stdin == nil {
		return nil, errors.New("no password on stdin")
	}
	line, err := bufio.NewReader(env.Stdin).ReadBytes('\n')
	if len(line) == 0 && err != nil {
		return nil, errors.New("no password on stdin")
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
	}
	return line, nil
}

func validateUserPassword(password []byte) error {
	if !utf8.Valid(password) {
		return errors.New("password must be valid UTF-8")
	}
	if utf8.RuneCount(password) < minLocalPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minLocalPasswordLen)
	}
	return nil
}

func runUserWith(ctx context.Context, env Env, args []string, deps userDeps) int {
	if len(args) == 0 {
		return userUsage(env)
	}
	subcommand := args[0]
	opts, ok := parseUserOptions(env, subcommand, args[1:])
	if !ok {
		if !isUserSubcommand(subcommand) {
			return userUsage(env)
		}
		return 2
	}

	fail := func(err error) int {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 1
	}
	now := time.Now().UTC()

	switch subcommand {
	case "create":
		password, err := readUserPassword(env)
		if err != nil {
			return fail(err)
		}
		defer crypto.Zero(password)
		if err := validateUserPassword(password); err != nil {
			return fail(err)
		}
		passwordHash, err := deps.hasher.Hash(ctx, string(password))
		if err != nil {
			return fail(err)
		}
		user := auth.User{
			ID:           uuid.New(),
			Username:     opts.username,
			DisplayName:  opts.displayName,
			Provider:     auth.ProviderLocal,
			PasswordHash: passwordHash,
			IsAdmin:      opts.admin,
			CreatedAt:    now,
		}
		if err := deps.users.Create(ctx, user); err != nil {
			return fail(err)
		}
		deps.sink.Record(ctx, audit.Event{
			At:      now,
			Event:   audit.UserCreated,
			ActorID: &user.ID,
			Outcome: audit.OutcomeSuccess,
			Details: map[string]any{"username": user.Username, "admin": user.IsAdmin, "via": "cli"},
		})
		fmt.Fprintf(env.Stdout, "created user %s (%s)\n", user.Username, user.ID)
		return 0

	case "set-password":
		user, err := deps.users.GetByUsername(ctx, opts.username)
		if err != nil {
			return fail(err)
		}
		if user.Provider != auth.ProviderLocal {
			return fail(errors.New("passwords can only be set for local users"))
		}
		password, err := readUserPassword(env)
		if err != nil {
			return fail(err)
		}
		defer crypto.Zero(password)
		if err := validateUserPassword(password); err != nil {
			return fail(err)
		}
		passwordHash, err := deps.hasher.Hash(ctx, string(password))
		if err != nil {
			return fail(err)
		}
		if err := deps.users.SetPasswordHash(ctx, user.ID, passwordHash); err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.Stdout, "password updated for %s\n", user.Username)
		return 0

	case "disable", "enable":
		user, err := deps.users.GetByUsername(ctx, opts.username)
		if err != nil {
			return fail(err)
		}
		disabled := subcommand == "disable"
		if err := deps.users.SetDisabled(ctx, user.ID, disabled); err != nil {
			return fail(err)
		}
		if disabled {
			deps.sink.Record(ctx, audit.Event{
				At:      now,
				Event:   audit.UserDisabled,
				ActorID: &user.ID,
				Outcome: audit.OutcomeSuccess,
				Details: map[string]any{"username": user.Username, "via": "cli"},
			})
		}
		fmt.Fprintf(env.Stdout, "%s: disabled=%v\n", user.Username, disabled)
		return 0

	case "list":
		users, err := deps.users.List(ctx)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.Stdout, "%-36s %-24s %-8s %-5s %-8s %s\n", "ID", "USERNAME", "PROVIDER", "ADMIN", "DISABLED", "LAST_LOGIN")
		for _, user := range users {
			lastLogin := "-"
			if user.LastLoginAt != nil {
				lastLogin = user.LastLoginAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(env.Stdout, "%-36s %-24s %-8s %-5v %-8v %s\n", user.ID, user.Username, user.Provider, user.IsAdmin, user.Disabled, lastLogin)
		}
		return 0
	}
	return userUsage(env)
}
