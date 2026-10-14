package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/authority"
	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/gitinfo"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

const authorityUsage = "usage: saga-watchdog authority status | history | clear (--id ID | --all) --reason TEXT [--authorization-context NAME]"

// cliContext resolves the security context for operator commands from the
// same trusted sources a run uses: the invoking environment, the policy and
// the project root.
func cliContext(g gitinfo.Info, c config.Config, override string) (authority.Context, string, string, error) {
	projectID, err := store.ProjectID(g.Root)
	if err != nil {
		return authority.Context{}, "", "", err
	}
	dir, err := store.ProjectDir(g.Root)
	if err != nil {
		return authority.Context{}, "", "", err
	}
	name := c.Project.Name
	if name == "" {
		name = filepath.Base(g.Root)
	}
	authorizationContext := c.SecurityContext.AuthorizationContext
	if override != "" {
		authorizationContext = override
	}
	ctx, why := authority.Resolve(os.Getenv(authority.OperatorEnv), authorizationContext, projectID, name)
	return ctx, why, dir, nil
}

// insideRun reports the supervised run this process runs in, if any. An agent
// inherits these variables; an operator's terminal does not.
func insideRun() (string, string) {
	return os.Getenv("SAGA_WATCHDOG_RUN_ID"), os.Getenv("SAGA_WATCHDOG_SOCKET")
}

func authorityCLI(g gitinfo.Info, c config.Config, args []string) int {
	if len(args) == 0 {
		return fail(errors.New(authorityUsage))
	}
	f := flag.NewFlagSet("authority "+args[0], flag.ContinueOnError)
	id := f.String("id", "", "restriction ID to clear")
	all := f.Bool("all", false, "clear every restriction of the context")
	reason := f.String("reason", "", "why the operator clears the restriction (recorded)")
	override := f.String("authorization-context", "", "address another authorization context of this operator and project")
	if err := f.Parse(args[1:]); err != nil {
		return 2
	}
	if f.NArg() != 0 {
		return fail(errors.New(authorityUsage))
	}
	ctx, why, dir, err := cliContext(g, c, *override)
	if err != nil {
		return fail(err)
	}
	switch args[0] {
	case "status":
		fmt.Printf("Operator   %s\nProject    %s (%s)\nAuthz      %s\n", orNone(ctx.OperatorID), event.Redact(ctx.Project), ctx.ProjectID, orNone(ctx.AuthorizationContextID))
		if why != "" {
			fmt.Println("Context    none: cross-run authority correlation disabled (" + why + ")")
			return 0
		}
		fmt.Println("Context    " + ctx.ID())
		st, err := authority.Peek(dir, ctx)
		if err != nil {
			fmt.Println("FAIL", event.Redact(err.Error()))
			fmt.Println("An operator can move it aside with: saga-watchdog authority clear --all --reason <text>")
			return 2
		}
		now := time.Now().UTC()
		if len(st.Restrictions) == 0 {
			fmt.Println("No unresolved restrictions")
		}
		for _, r := range st.Restrictions {
			state := "until " + r.Expires.Format(time.RFC3339)
			if !r.Expires.After(now) {
				state = "expired"
			}
			fmt.Printf("%s  %-30s %-5s %s %s  run %s  attempts %d  %s\n", r.ID, r.Rule, r.Decision, r.Type, event.Redact(r.Target), r.RunID, r.Attempts, state)
			for _, l := range r.Related {
				fmt.Printf("    %s  %s: %s %s  run %s  session %s  instance %s  host %s\n", l.At.Format(time.RFC3339), l.Correlation, l.Type, event.Redact(l.Target), l.RunID, orNone(l.SessionID), l.InstanceID, l.HostID)
			}
		}
		return 0
	case "history":
		if why != "" {
			return fail(errors.New("no security context: " + why))
		}
		if err := authority.History(dir, ctx, os.Stdout); err != nil {
			return fail(err)
		}
		return 0
	case "clear":
	default:
		return fail(errors.New(authorityUsage))
	}
	// An agent can never clear its own history. From inside a supervised run
	// the attempt is refused and reported to that run as a security event.
	if runID, sock := insideRun(); runID != "" && sock != "" {
		socket.Send(sock, socket.Request{Operation: "check", RunID: runID, Event: socket.Input{Type: "authority", Action: "clear", Target: "persistent-state", Producer: "saga-watchdog"}})
		return fail(fmt.Errorf("refused: security history cannot be cleared from inside supervised run %s; the attempt was reported", runID))
	}
	if why != "" {
		return fail(errors.New("no security context: " + why))
	}
	if (*id == "") == !*all || *reason == "" || len(*reason) > 256 {
		return fail(errors.New(authorityUsage))
	}
	s, err := authority.Open(dir, ctx, c.SecurityContext.Retention, c.SecurityContext.SeriousRetention)
	if errors.Is(err, authority.ErrCorrupt) && *all {
		moved, err := authority.QuarantineCorrupt(dir, ctx, ctx.OperatorID, *reason)
		if err != nil {
			return fail(err)
		}
		fmt.Println("Moved unreadable state aside:", moved)
		return 0
	}
	if err != nil {
		return fail(err)
	}
	cleared, err := s.Clear(time.Now().UTC(), *id, ctx.OperatorID, *reason)
	if err != nil {
		return fail(err)
	}
	if *id != "" && len(cleared) == 0 {
		return fail(fmt.Errorf("no restriction %s in context %s", *id, ctx.ID()))
	}
	for _, r := range cleared {
		fmt.Printf("Cleared %s (%s %s %s) by %s: %s\n", r.ID, r.Rule, r.Type, event.Redact(r.Target), ctx.OperatorID, event.Redact(*reason))
	}
	if len(cleared) == 0 {
		fmt.Println("No unresolved restrictions")
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// doctorAuthority reports whether persistent security correlation can be
// trusted. Missing identity disables it; it is never guessed.
func doctorAuthority(g gitinfo.Info, c config.Config) int {
	ctx, why, dir, err := cliContext(g, c, "")
	if err != nil {
		fmt.Println("FAIL project identity:", event.Redact(err.Error()))
		return 2
	}
	fmt.Printf("OK project identity %s (%s)\n", event.Redact(ctx.Project), ctx.ProjectID)
	if ctx.OperatorID != "" {
		fmt.Println("OK operator identity from " + authority.OperatorEnv + ": " + ctx.OperatorID)
	} else {
		fmt.Println("! operator identity unavailable (set " + authority.OperatorEnv + "=human:<name> when invoking saga-watchdog)")
	}
	if ctx.AuthorizationContextID != "" {
		fmt.Println("OK authorization context from policy: " + ctx.AuthorizationContextID)
	} else {
		fmt.Println("! no authorization context (security_context.authorization_context in the policy)")
	}
	if runID, _ := insideRun(); runID != "" {
		fmt.Println("! running inside supervised run " + runID + ": a nested run must be authorized by it and inherits its context")
	}
	if why != "" {
		fmt.Println("! cross-run authority correlation disabled: " + why)
		return 0
	}
	st, err := authority.Peek(dir, ctx)
	if err != nil {
		fmt.Println("FAIL persistent authority state:", event.Redact(err.Error()))
		return 2
	}
	fmt.Printf("OK persistent authority correlation enabled for %s (%d restrictions on record)\n", ctx.ID(), len(st.Restrictions))
	return 0
}
