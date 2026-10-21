package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/gitinfo"
	"github.com/odbgrowth/saga-watchdog/internal/integrations"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
	"github.com/odbgrowth/saga-watchdog/internal/sources/filesystem"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
	"github.com/odbgrowth/saga-watchdog/internal/supervisor"
)

const usage = `SAGA Watchdog: local deterministic agent supervisor

Usage:
  saga-watchdog init | validate | doctor | version
  saga-watchdog run -- <command> [args...]
  saga-watchdog status [--run ID]
  saga-watchdog events [--run ID]
  saga-watchdog report [--run ID] [--json]
  saga-watchdog pause|resume|kill <run-id>
  saga-watchdog grant [--run ID] network <host> | tool <server/tool>
  saga-watchdog authority status | history | clear (--id ID | --all) --reason TEXT
  saga-watchdog check --type TYPE --action ACTION --target TARGET [--host H] [--runtime-type T] [--run ID]
  saga-watchdog emit --type TYPE --action ACTION --target TARGET --result RESULT [--host H] [--runtime-type T] [--instance ID] [--run ID]
  saga-watchdog claude config | setup [--local] | remove [--local] | doctor
  saga-watchdog codex  config | setup | remove | doctor
  saga-watchdog gemini config | setup | remove | doctor
  saga-watchdog claude|codex|gemini hook   (run by the agent's hooks; reads stdin)
  saga-watchdog docker validate|watch|status|events --config FILE
  saga-watchdog docker watch --config FILE --once

Linux and macOS process supervision. No file-read or raw network monitoring.
Claude Code, Codex CLI and Gemini CLI can ask SAGA before supported tool
calls; see docs/claude-code.md, docs/codex.md and docs/gemini-cli.md.
Docker observation uses a separate config and needs no Git repository.
`

func main() { os.Exit(cli(os.Args[1:])) }

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "saga-watchdog:", event.Redact(err.Error()))
	return 2
}

func cli(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	if args[0] == "version" {
		fmt.Println("saga-watchdog", version)
		return 0
	}
	if args[0] == "docker" {
		return dockerCLI(args[1:])
	}
	for _, spec := range integrations.Specs {
		if args[0] == spec.Agent {
			return agentCLI(spec, args[1:])
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	g, err := gitinfo.Inspect(cwd)
	if err != nil {
		switch args[0] {
		case "status", "events", "report", "check", "emit", "pause", "resume", "kill", "grant", "authority":
			// Controls must still work from the original project root if Git metadata
			// was deleted or corrupted. They contact a live supervisor, never a PID.
			root, resolveErr := filepath.EvalSymlinks(cwd)
			if resolveErr != nil {
				return fail(resolveErr)
			}
			g = gitinfo.Info{Root: root}
		default:
			return fail(err)
		}
	}
	switch args[0] {
	case "init":
		if len(args) != 1 {
			return fail(errors.New("init takes no arguments"))
		}
		p := filepath.Join(g.Root, config.Filename)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fail(fmt.Errorf("create policy (existing files are preserved): %w", err))
		}
		_, err = f.WriteString(config.DefaultYAML)
		closeErr := f.Close()
		if err != nil {
			return fail(err)
		}
		if closeErr != nil {
			return fail(closeErr)
		}
		fmt.Println("Created", p)
		fmt.Println("Inspect the policy, then run: saga-watchdog doctor")
		return 0
	case "authority":
		c, _, err := load(g.Root)
		if err != nil {
			return fail(err)
		}
		return authorityCLI(g, c, args[1:])
	case "validate", "doctor", "run":
		c, hash, err := load(g.Root)
		if err != nil {
			return fail(err)
		}
		if args[0] != "run" && len(args) != 1 {
			return fail(errors.New("unexpected arguments"))
		}
		if args[0] == "validate" {
			fmt.Println("Configuration valid")
			return 0
		}
		if args[0] == "doctor" {
			return doctor(g, c)
		}
		if len(args) < 3 || args[1] != "--" {
			return fail(errors.New("usage: saga-watchdog run -- <command> [args...]"))
		}
		return run(g, c, hash, args[2:])
	case "status", "events", "report", "check", "emit":
		return query(g, args[0], args[1:])
	case "grant":
		return grant(g, args[1:])
	case "pause", "resume", "kill":
		if len(args) != 2 {
			return fail(fmt.Errorf("usage: saga-watchdog %s <run-id>", args[0]))
		}
		_, r, err := store.Locate(g.Root, args[1])
		if err != nil {
			return fail(err)
		}
		response, err := socket.Send(r.Control, socket.Request{Operation: args[0], RunID: r.ID})
		if err != nil {
			return fail(err)
		}
		if response.Run != nil {
			printRun(*response.Run)
		}
		return 0
	default:
		return fail(fmt.Errorf("unknown command %q; use --help", args[0]))
	}
}

func load(root string) (config.Config, string, error) {
	p := filepath.Join(root, config.Filename)
	info, err := os.Lstat(p)
	if err != nil {
		return config.Config{}, "", fmt.Errorf("read policy (run saga-watchdog init first): %w", err)
	}
	if !info.Mode().IsRegular() {
		return config.Config{}, "", errors.New("policy must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
		return config.Config{}, "", errors.New("policy must not be writable by group or others; use chmod go-w .saga-watchdog.yaml")
	}
	f, err := os.Open(p)
	if err != nil {
		return config.Config{}, "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return config.Config{}, "", err
	}
	if len(b) > 65536 {
		return config.Config{}, "", errors.New("policy exceeds 64 KiB")
	}
	c, err := config.Parse(bytes.NewReader(b))
	h := sha256.Sum256(b)
	return c, hex.EncodeToString(h[:]), err
}

func doctor(g gitinfo.Info, c config.Config) int {
	fmt.Println("OK configuration valid; policy permissions checked")
	fmt.Printf("OK Git repository; branch %s; dirty %t; remotes %d\n", event.Redact(g.Branch), g.Dirty, len(g.Remotes))
	code := 0
	if gitinfo.Protected(g.Branch, c.Git.ProtectedBranches) && !c.Git.AllowProtected {
		fmt.Println("FAIL protected branch: create a working branch before starting an agent")
		code = 2
	}
	if _, err := store.Prepare(g.Root); err != nil {
		fmt.Println("FAIL state directory:", event.Redact(err.Error()))
		code = 2
	} else {
		fmt.Println("OK private state directory writable")
	}
	if supervisor.Supported() {
		fmt.Println("OK process-group pause/resume/termination supported")
	} else {
		fmt.Println("FAIL process supervision is supported only on Linux/macOS")
		code = 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	source, err := filesystem.Start(ctx, g, c, make(chan event.Event, 64), make(chan error, 1))
	if err != nil {
		fmt.Println("FAIL filesystem monitoring:", event.Redact(err.Error()))
		code = 2
	} else {
		fmt.Println("OK filesystem change monitoring available")
		source.Close()
	}
	cancel()
	controls := integrations.Controls(g.Root)
	for _, spec := range integrations.Specs {
		var files []string
		for _, file := range spec.Files {
			if slices.Contains(controls, file) {
				files = append(files, file)
			}
		}
		if len(files) > 0 {
			fmt.Printf("OK %s preventive hook configured in %s (verify: saga-watchdog %s doctor)\n", spec.Name, strings.Join(files, ", "), spec.Agent)
		}
	}
	if len(controls) == 0 {
		fmt.Println("! No preventive agent hook; supervision and observation only (optional: saga-watchdog claude|codex|gemini setup)")
	}
	if doctorAuthority(g, c) != 0 {
		code = 2
	}
	if c.Run.RequirePreventiveHook {
		fmt.Println("OK run.require_preventive_hook: run refuses to start unless the launched agent's own hook is configured and ready (saga-watchdog claude|codex|gemini doctor)")
	}
	ctxID, disabled, _, err := cliContext(g, c, "")
	contextID := ""
	if err == nil && disabled == "" {
		contextID = ctxID.ID()
	}
	fmt.Println("Coverage")
	for _, line := range coverage(c, controls, contextID, disabled) {
		fmt.Println("  " + line)
	}
	fmt.Println("! Integrations report events; they do not prove OS actions occurred")
	fmt.Println("! Same-user separation is not a sandbox")
	fmt.Println("Core protection level: LOCAL")
	return code
}

func query(g gitinfo.Info, op string, args []string) int {
	f := flag.NewFlagSet(op, flag.ContinueOnError)
	id := f.String("run", "", "run ID (latest in this project by default)")
	asJSON := false
	if op == "report" {
		f.BoolVar(&asJSON, "json", false, "print the report as JSON")
	}
	var input socket.Input
	if op == "check" || op == "emit" {
		f.StringVar(&input.Type, "type", "", "event type")
		f.StringVar(&input.Action, "action", "", "action")
		f.StringVar(&input.Target, "target", "", "target")
		f.StringVar(&input.Host, "host", "", "host a runtime starts or executes on (agent, runtime, inference, remote events)")
		f.StringVar(&input.RuntimeType, "runtime-type", "", "agent, worker, model-server or inference-endpoint")
		if op == "emit" {
			f.StringVar(&input.Result, "result", "", "observed result")
			f.StringVar(&input.Instance, "instance", "", "instance a stop ends or a start report confirms, as returned for its start check")
		}
	}
	if err := f.Parse(args); err != nil {
		return 2
	}
	if f.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	if (op == "check" || op == "emit") && *id == "" && os.Getenv("SAGA_WATCHDOG_SOCKET") != "" {
		return sendEvent(os.Getenv("SAGA_WATCHDOG_SOCKET"), "", op, input)
	}
	dir, r, err := store.Locate(g.Root, *id)
	if err != nil {
		return fail(err)
	}
	switch op {
	case "report":
		// Run state is persisted on a one-second ticker; the supervisor has the
		// current one while the run is active.
		if r.Finished == nil {
			if live, err := socket.Send(r.Control, socket.Request{Operation: "status", RunID: r.ID}); err == nil && live.Run != nil {
				r = *live.Run
			}
		}
		return report(dir, r, asJSON)
	case "events":
		f, err := os.Open(filepath.Join(dir, "events.jsonl"))
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		if _, err = io.Copy(os.Stdout, f); err != nil {
			return fail(err)
		}
		return 0
	case "status":
		if r.Finished == nil {
			live, err := socket.Send(r.Control, socket.Request{Operation: "status", RunID: r.ID})
			if err != nil {
				r.Status = "unreachable (last recorded: " + r.Status + ")"
				printRun(r)
				return 2
			}
			if live.Run != nil {
				r = *live.Run
			}
		}
		printRun(r)
		return 0
	default:
		return sendEvent(r.Socket, r.ID, op, input)
	}
}

func sendEvent(path, id, op string, input socket.Input) int {
	request := socket.Request{Operation: op, RunID: id, Event: input}
	if err := socket.Validate(request, false); err != nil {
		return fail(err)
	}
	response, err := socket.Send(path, request)
	if err != nil {
		return fail(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(response); err != nil {
		return fail(err)
	}
	if op == "check" && !response.Allowed {
		return 3
	}
	return 0
}

func printRun(r store.Run) {
	fmt.Printf("Run       %s\nProject   %s\nAgent     %s\nStatus    %s\nEvents    %d\nWarnings  %d\nPauses    %d\nKills     %d\n", r.ID, event.Redact(r.Project), event.Redact(r.Agent), r.Status, r.Events, r.Warnings, r.Pauses, r.Kills)
	if r.Reason != "" {
		fmt.Printf("Rule      %s\nReason    %s\n", r.Rule, event.Redact(r.Reason))
	}
	if len(r.Grants) > 0 {
		fmt.Printf("Grants    %s\n", event.Redact(strings.Join(r.Grants, ", ")))
	}
	if r.Instance != nil {
		line := r.Instance.ID + " (provenance " + r.Instance.Provenance
		if r.Instance.ParentID != "" {
			line += ", parent " + r.Instance.ParentID
		}
		fmt.Printf("Instance  %s)\n", line)
	}
	if r.ContextID != "" {
		fmt.Printf("Context   %s\n", r.ContextID)
	} else if r.ContextDisabled != "" {
		fmt.Printf("Context   none (%s)\n", r.ContextDisabled)
	}
}

// grant authorizes one network host or tool identifier for the rest of a run
// through the control socket. It is the operator's answer to a run paused by
// network-unlisted or tool-unlisted; the run still needs an explicit resume.
func grant(g gitinfo.Info, args []string) int {
	f := flag.NewFlagSet("grant", flag.ContinueOnError)
	id := f.String("run", "", "run ID (latest in this project by default)")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if f.NArg() != 2 || (f.Arg(0) != "network" && f.Arg(0) != "tool") {
		return fail(errors.New("usage: saga-watchdog grant [--run ID] network <host> | tool <server/tool>"))
	}
	_, r, err := store.Locate(g.Root, *id)
	if err != nil {
		return fail(err)
	}
	response, err := socket.Send(r.Control, socket.Request{Operation: "grant", RunID: r.ID, Event: socket.Input{Type: f.Arg(0), Target: f.Arg(1)}})
	if err != nil {
		return fail(err)
	}
	if response.Run != nil {
		printRun(*response.Run)
	}
	fmt.Printf("Granted for this run only. If the run is paused: saga-watchdog resume %s\n", r.ID)
	return 0
}

func permits(mode string, d policy.Decision) bool {
	return mode == "observe" || d.Action == "allow" || d.Action == "warn"
}
