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
	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
)

// claudeCLI serves the Claude Code integration. `hook` is the command Claude
// Code runs on every matched tool call; it must stay fast and must not depend
// on Git inspection, so it is dispatched before any repository lookup.
func claudeCLI(args []string) int {
	if len(args) == 0 {
		return fail(errors.New("usage: saga-watchdog claude hook|config|setup [--local]|doctor"))
	}
	switch args[0] {
	case "hook":
		if len(args) != 1 {
			return fail(errors.New("hook reads one Claude Code event from stdin and takes no arguments"))
		}
		return claudecode.Main()
	case "config":
		if len(args) != 1 {
			return fail(errors.New("config takes no arguments"))
		}
		os.Stdout.Write(claudecode.SettingsJSON())
		fmt.Fprintln(os.Stderr, "Merge this into .claude/settings.json in the project, or run: saga-watchdog claude setup")
		return 0
	case "setup", "doctor":
	default:
		return fail(fmt.Errorf("unknown claude command %q; use hook, config, setup or doctor", args[0]))
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
		return claudeDoctor(g, c)
	}
	f := flag.NewFlagSet("claude setup", flag.ContinueOnError)
	local := f.Bool("local", false, "write .claude/settings.local.json (gitignored) instead of .claude/settings.json")
	if err := f.Parse(args[1:]); err != nil {
		return 2
	}
	if f.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	name := claudecode.Files[0]
	if *local {
		name = claudecode.Files[1]
	}
	path := filepath.Join(g.Root, filepath.FromSlash(name))
	changed, err := claudecode.Setup(path)
	if err != nil {
		return fail(fmt.Errorf("existing settings are preserved: %w", err))
	}
	if changed {
		fmt.Println("Updated", path)
	} else {
		fmt.Println("Already configured:", path)
	}
	fmt.Println("Inspect the hooks, then run: saga-watchdog claude doctor")
	fmt.Println("Start Claude Code under supervision with: saga-watchdog run -- claude")
	return 0
}

func claudeDoctor(g gitinfo.Info, c config.Config) int {
	code := doctor(g, c)
	check := func(ok bool, pass, failure string) {
		if ok {
			fmt.Println("OK", pass)
			return
		}
		fmt.Println("FAIL", failure)
		code = 2
	}
	_, err := exec.LookPath("saga-watchdog")
	check(err == nil, "saga-watchdog is on PATH for the hook command", "saga-watchdog is not on PATH; the hook command cannot start")
	claudePath, err := exec.LookPath("claude")
	check(err == nil, "claude executable found", "claude executable not found on PATH")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, claudePath, "--version").Output()
		version := claudecode.Version(string(out))
		switch {
		case err != nil || version == "":
			fmt.Println("! claude --version failed; compatibility not verified")
		case claudecode.AtLeast(version, claudecode.MinimumVersion):
			fmt.Printf("OK Claude Code %s supports onFailure: block (fail-closed hooks)\n", version)
		default:
			fmt.Printf("! Claude Code %s predates %s; Claude cannot fail closed on hook errors, only the adapter does\n", version, claudecode.MinimumVersion)
		}
	}
	configured := false
	for _, s := range claudecode.Inspect(g.Root) {
		path := filepath.Join(g.Root, filepath.FromSlash(s.File))
		switch {
		case s.Err != nil:
			check(false, "", s.File+": "+event.Redact(s.Err.Error()))
		case s.Disabled:
			check(false, "", s.File+" sets disableAllHooks; the SAGA hook does not run")
		case !s.Configured:
			continue
		}
		if !s.Configured {
			continue
		}
		configured = true
		check(s.Preventive, s.File+" runs the SAGA PreToolUse hook with onFailure: block", s.File+" references SAGA but PreToolUse lacks onFailure: block or uses another matcher; compare with: saga-watchdog claude config")
		if info, err := os.Lstat(path); err == nil && runtime.GOOS != "windows" {
			check(info.Mode().Perm()&0022 == 0, s.File+" is not group/other writable", s.File+" is writable by group or others; use chmod go-w "+s.File)
		}
	}
	if !configured {
		check(false, "", "no SAGA hook in "+strings.Join(claudecode.Files, " or ")+"; run: saga-watchdog claude setup")
	}
	if c.Mode == "observe" {
		fmt.Println("! mode: observe; pre-action checks record decisions but allow every tool call")
	}
	fmt.Println("! Only matched tools are checked before execution; Bash commands, MCP arguments and file reads are not interpreted")
	fmt.Println("! Hooks run inside Claude's trusted-workspace rules; confirm the hook appears under /hooks in Claude Code")
	return code
}
