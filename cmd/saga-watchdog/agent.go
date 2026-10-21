package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/gitinfo"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/codex"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/gemini"
)

// hookMain maps an agent to its adapter entry point. `hook` is the command the
// agent runs on every matched tool call; it must stay fast and must not depend
// on Git inspection, so it is dispatched before any repository lookup.
var hookMain = map[string]func() int{"claude": claudecode.Main, "codex": codex.Main, "gemini": gemini.Main}

// agentCLI serves one agent's integration commands.
func agentCLI(spec *agenthook.Spec, args []string) int {
	local := spec.Agent == "claude"
	usage := "usage: saga-watchdog " + spec.Agent + " hook|config|setup|remove|doctor"
	if local {
		usage = "usage: saga-watchdog claude hook|config|setup [--local]|remove [--local]|doctor"
	}
	if len(args) == 0 {
		return fail(errors.New(usage))
	}
	switch args[0] {
	case "hook":
		if len(args) != 1 {
			return fail(errors.New("hook reads one hook event from stdin and takes no arguments"))
		}
		return hookMain[spec.Agent]()
	case "config":
		if len(args) != 1 {
			return fail(errors.New("config takes no arguments"))
		}
		os.Stdout.Write(spec.SettingsJSON())
		fmt.Fprintf(os.Stderr, "Merge this into %s in the project, or run: saga-watchdog %s setup\n", spec.Files[0], spec.Agent)
		return 0
	case "setup", "remove", "doctor":
	default:
		return fail(fmt.Errorf("unknown %s command %q; use hook, config, setup, remove or doctor", spec.Agent, args[0]))
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	g, err := gitinfo.Inspect(cwd)
	if err != nil {
		return fail(err)
	}
	if args[0] == "doctor" {
		if len(args) != 1 {
			return fail(errors.New("doctor takes no arguments"))
		}
		c, _, err := load(g.Root)
		if err != nil {
			return fail(err)
		}
		return agentDoctor(spec, g, c)
	}
	f := flag.NewFlagSet(spec.Agent+" "+args[0], flag.ContinueOnError)
	useLocal := false
	if local {
		f.BoolVar(&useLocal, "local", false, "use .claude/settings.local.json (gitignored) instead of .claude/settings.json")
	}
	if err := f.Parse(args[1:]); err != nil {
		return 2
	}
	if f.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	name := spec.Files[0]
	if useLocal {
		name = spec.Files[1]
	}
	path := filepath.Join(g.Root, filepath.FromSlash(name))
	if args[0] == "remove" {
		changed, err := spec.Remove(path)
		if err != nil {
			return fail(fmt.Errorf("existing settings are preserved: %w", err))
		}
		if changed {
			fmt.Println("Removed the SAGA hooks from", path)
		} else {
			fmt.Println("No SAGA hooks in", path)
		}
		fmt.Println("Do this only between runs; changing the file during a supervised run is hook tampering")
		return 0
	}
	changed, err := spec.Setup(path)
	if err != nil {
		return fail(fmt.Errorf("existing settings are preserved: %w", err))
	}
	if changed {
		fmt.Println("Updated", path)
	} else {
		fmt.Println("Already configured:", path)
	}
	fmt.Printf("Inspect the hooks, then run: saga-watchdog %s doctor\n", spec.Agent)
	if spec.Agent == "codex" {
		fmt.Println("Codex runs a new project hook only after you accept it once in its interactive startup review")
	}
	fmt.Printf("Start the agent under supervision with: saga-watchdog run -- %s\n", spec.Agent)
	return 0
}

func agentDoctor(spec *agenthook.Spec, g gitinfo.Info, c config.Config) int {
	code := doctor(g, c)
	ready := hookReadiness(spec, g.Root)
	for _, ch := range ready.checks {
		if ch.ok {
			fmt.Println("OK", ch.text)
		} else {
			fmt.Println("FAIL", ch.text)
			code = 2
		}
	}
	for _, note := range ready.notes {
		fmt.Println("!", note)
	}
	if c.Mode == "observe" {
		fmt.Println("! mode: observe; pre-action checks record decisions but allow every tool call")
	}
	switch spec.Agent {
	case "claude":
		fmt.Println("! Only matched tools are checked before execution; Bash commands, MCP arguments and file reads are not interpreted")
		fmt.Println("! Hooks run inside Claude's trusted-workspace rules; confirm the hook appears under /hooks in Claude Code")
	case "codex":
		fmt.Println("! Codex skips an untrusted project hook: accept it once in the interactive startup review before headless codex exec runs")
		fmt.Println("! Codex cannot fail closed when the adapter is missing or times out; keep saga-watchdog on PATH")
		fmt.Println("! Shell commands and MCP arguments are not interpreted; apply_patch is checked per named file")
	case "gemini":
		fmt.Println("! Gemini CLI runs project hooks only in a trusted folder and cannot fail closed when the adapter is missing or times out")
		fmt.Println("! Shell commands, MCP arguments and prompt-only web_fetch calls are not interpreted")
	}
	return code
}

// readiness is what SAGA can check locally about one agent's preventive hook
// before a run: the executables, the agent's version or feature flags and
// the project hook configuration. Each check passes or fails with the text
// the doctor prints; notes are facts that neither pass nor fail. It is a
// lexical check of files and CLI output, not proof that the agent loads or
// honours the hook.
type readiness struct {
	checks []readinessCheck
	notes  []string
}

type readinessCheck struct {
	ok   bool
	text string
}

func (r *readiness) check(ok bool, pass, failure string) {
	text := failure
	if ok {
		text = pass
	}
	r.checks = append(r.checks, readinessCheck{ok: ok, text: text})
}

// fail records a check that can only fail.
func (r *readiness) fail(text string) { r.check(false, "", text) }

// problems lists the failed checks.
func (r readiness) problems() []string {
	var out []string
	for _, ch := range r.checks {
		if !ch.ok {
			out = append(out, ch.text)
		}
	}
	return out
}

// hookReadiness runs the agent-specific pre-flight checks that the agent
// doctor prints and run.require_preventive_hook refuses on.
func hookReadiness(spec *agenthook.Spec, root string) readiness {
	var r readiness
	_, err := exec.LookPath("saga-watchdog")
	r.check(err == nil, "saga-watchdog is on PATH for the hook command", "saga-watchdog is not on PATH; the hook command cannot start")
	agentPath, err := exec.LookPath(spec.Agent)
	r.check(err == nil, spec.Agent+" executable found", spec.Agent+" executable not found on PATH")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		switch spec.Agent {
		case "claude":
			out, err := exec.CommandContext(ctx, agentPath, "--version").Output()
			version := claudecode.Version(string(out))
			switch {
			case err != nil || version == "":
				r.notes = append(r.notes, "claude --version failed; compatibility not verified")
			default:
				r.check(claudecode.AtLeast(version, claudecode.MinimumVersion), fmt.Sprintf("Claude Code %s supports onFailure: block (can block when the hook cannot run)", version), fmt.Sprintf("Claude Code %s predates %s; Claude cannot fail closed on hook errors, only the adapter does; upgrade Claude Code", version, claudecode.MinimumVersion))
			}
		case "codex":
			// The hooks feature flag is reported by the CLI itself; a build that
			// disables it never runs the hook.
			out, err := exec.CommandContext(ctx, agentPath, "features", "list").Output()
			if err != nil {
				r.notes = append(r.notes, "codex features list failed; hooks feature not verified")
			} else {
				r.check(featureEnabled(string(out), "hooks"), "codex reports the hooks feature enabled", "codex reports the hooks feature disabled; enable it with: codex features enable hooks")
			}
		case "gemini":
			out, err := exec.CommandContext(ctx, agentPath, "--version").Output()
			if version := claudecode.Version(string(out)); err != nil || version == "" {
				r.notes = append(r.notes, "gemini --version failed; compatibility not verified")
			} else {
				r.notes = append(r.notes, fmt.Sprintf("Gemini CLI %s found (hook contract verified with 0.63.0)", version))
			}
		}
	}
	configured := false
	for _, s := range spec.Inspect(root) {
		path := filepath.Join(root, filepath.FromSlash(s.File))
		switch {
		case s.Err != nil:
			r.fail(s.File + ": " + event.Redact(s.Err.Error()))
		case s.Disabled:
			r.fail(s.File + " disables hooks; the SAGA hook does not run")
		}
		if !s.Configured {
			continue
		}
		configured = true
		want := "runs the SAGA " + spec.PreEvent + " hook with the expected matcher"
		if spec.FailClosed != "" {
			want = "runs the SAGA " + spec.PreEvent + " hook with onFailure: block"
		}
		r.check(s.Preventive, s.File+" "+want, s.File+" references SAGA but "+spec.PreEvent+" is missing, uses another matcher or cannot block; compare with: saga-watchdog "+spec.Agent+" config")
		if info, err := os.Lstat(path); err == nil && runtime.GOOS != "windows" {
			r.check(info.Mode().Perm()&0022 == 0, s.File+" is not group/other writable", s.File+" is writable by group or others; use chmod go-w "+s.File)
		}
	}
	if !configured {
		r.fail("no SAGA hook in " + strings.Join(spec.Files, " or ") + "; run: saga-watchdog " + spec.Agent + " setup")
	}
	return r
}

// featureEnabled reads one row of `codex features list`: name, stage, state.
func featureEnabled(out, name string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == name {
			return fields[len(fields)-1] == "true"
		}
	}
	return false
}
