// Package cli dispatches pastebin subcommands. Subcommands register
// themselves with Register so workstreams can add commands without
// touching this file.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/knumchoke/secure-pastebin/internal/version"
)

// Env is everything a command may touch from the outside world.
type Env struct {
	Getenv func(string) string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Command runs a subcommand and returns a process exit code.
type Command func(ctx context.Context, env Env, args []string) int

var registry = map[string]Command{}

// Register adds a subcommand. Panics on duplicate names (programming error).
func Register(name string, fn Command) {
	if _, dup := registry[name]; dup {
		panic("cli: duplicate command " + name)
	}
	registry[name] = fn
}

func init() {
	Register("version", func(_ context.Context, env Env, _ []string) int {
		fmt.Fprintf(env.Stdout, "pastebin %s\n", version.Version)
		return 0
	})
}

func usage(w io.Writer) {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintln(w, "usage: pastebin <command> [flags]")
	fmt.Fprintln(w, "commands:")
	for _, n := range names {
		fmt.Fprintf(w, "  %s\n", n)
	}
}

// Run executes args[0] as a subcommand. It installs SIGINT/SIGTERM
// cancellation on the context passed to the command.
func Run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, ok := registry[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cmd(ctx, Env{Getenv: getenv, Stdin: stdin, Stdout: stdout, Stderr: stderr}, args[1:])
}
