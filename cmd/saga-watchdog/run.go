package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/gitinfo"
	"github.com/odbgrowth/saga-watchdog/internal/integrations"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
	"github.com/odbgrowth/saga-watchdog/internal/sources/filesystem"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
	"github.com/odbgrowth/saga-watchdog/internal/supervisor"
)

func run(g gitinfo.Info, c config.Config, hash string, command []string) int {
	if !supervisor.Supported() {
		return fail(fmt.Errorf("run requires Linux or macOS; Windows is unsupported"))
	}
	if gitinfo.Protected(g.Branch, c.Git.ProtectedBranches) && !c.Git.AllowProtected {
		return fail(fmt.Errorf("protected branch: create a working branch or explicitly set git.allow_protected in policy"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	name := c.Project.Name
	if name == "" {
		name = filepath.Base(g.Root)
	}
	r := store.Run{ID: event.NewID("run"), Project: name, Agent: filepath.Base(command[0]), Status: "starting", Mode: c.Mode, Branch: g.Branch, PolicyHash: hash, Started: time.Now().UTC()}
	audit, err := store.Create(g.Root, r)
	if err != nil {
		return fail(err)
	}
	finish := func(status, reason string, code int) int {
		end := time.Now().UTC()
		r.Finished = &end
		r.Status = status
		r.Reason = reason
		r.ExitCode = code
		for _, summary := range []bool{false, true} {
			if err := audit.Save(r, summary); err != nil {
				fmt.Fprintln(os.Stderr, "state write:", event.Redact(err.Error()))
				code = 125
			}
		}
		if err := audit.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "audit flush:", event.Redact(err.Error()))
			code = 125
		}
		fmt.Fprintf(os.Stderr, "\nSAGA Watchdog summary\nDuration    %s\nRun exit    %d\nEvents      %d\nWarnings    %d\nViolations  %d\nResult      %s\n", end.Sub(r.Started).Round(time.Millisecond), code, r.Events, r.Warnings, r.Violations, status)
		if reason != "" {
			fmt.Fprintf(os.Stderr, "Rule        %s\nReason      %s\n", r.Rule, event.Redact(reason))
		}
		return code
	}
	queue := make(chan event.Event, 256)
	failures := make(chan error, 4)
	calls := make(chan socket.Call, 32)
	ipc, err := socket.Start(ctx, calls)
	if err != nil {
		return finish("failed", err.Error(), 125)
	}
	defer ipc.Close()
	r.Socket = ipc.Events
	r.Control = ipc.Control
	source, err := filesystem.Start(ctx, g, c, queue, failures)
	if err != nil {
		return finish("failed", err.Error(), 125)
	}
	defer source.Close()
	// Read again after sources are ready, closing the initialization blind window.
	_, currentHash, err := load(g.Root)
	if err != nil || currentHash != hash {
		return finish("failed", "policy changed during startup", 125)
	}
	// Settings files that run the SAGA hook configure a preventive integration
	// for this run. They are fingerprinted now, after the observer is live, and
	// protected like the policy file until the run ends.
	r.Controls = integrations.Controls(g.Root)
	controlsDigest := map[string]string{}
	if len(r.Controls) > 0 {
		// Once a hook is active every agent configuration file matters: a
		// sibling can disable it. Fingerprint all of them, not only the carrier.
		for _, name := range integrations.Files() {
			controlsDigest[name] = agenthook.Digest(g.Root, []string{name})
		}
	}
	env := make([]string, 0, len(os.Environ())+2)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "SAGA_WATCHDOG_SOCKET=") && !strings.HasPrefix(v, "SAGA_WATCHDOG_RUN_ID=") {
			env = append(env, v)
		}
	}
	env = append(env, "SAGA_WATCHDOG_SOCKET="+ipc.Events, "SAGA_WATCHDOG_RUN_ID="+r.ID)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	process, err := supervisor.Start(command, g.Root, env, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return finish("failed", err.Error(), 125)
	}
	stopAndWait := func() {
		stopErr := process.Stop(c.Run.StopGracePeriod)
		// Stop sends the final signal; Done also guarantees reaping and terminal
		// restoration. A second receive after the run loop consumed Done is safe.
		<-process.Done()
		if stopErr != nil {
			fmt.Fprintln(os.Stderr, "process stop:", event.Redact(stopErr.Error()))
		}
	}
	defer stopAndWait()
	r.Status = "running"
	engine := policy.New(c, g.Root, r.Controls...)
	record := func(e event.Event, d policy.Decision) error {
		e.ID = event.NewID("evt")
		e.RunID = r.ID
		e.ProjectID = name
		e.Timestamp = time.Now().UTC()
		e.RuleID = d.RuleID
		e.Severity = d.Severity
		if e.Metadata == nil {
			e.Metadata = map[string]any{}
		}
		e.Metadata["decision"] = d.Action
		e.Metadata["reason"] = d.Reason
		e.Metadata["mode"] = c.Mode
		if err := audit.Append(e); err != nil {
			return err
		}
		r.Events++
		if d.Action != "allow" {
			r.Violations++
			if d.Action == "warn" {
				r.Warnings++
			}
		}
		return nil
	}
	if err = record(event.Event{Source: "supervisor", Type: "process", Action: "start", Target: r.Agent, Result: "success"}, policy.Decision{Action: "allow", Severity: "info"}); err != nil {
		stopAndWait()
		return finish("failed", err.Error(), 125)
	}
	if err = audit.Save(r, false); err != nil {
		stopAndWait()
		return finish("failed", err.Error(), 125)
	}
	hooks := "none (supervision and observation only)"
	if len(r.Controls) > 0 {
		hooks = "claude-code via " + strings.Join(r.Controls, ", ")
	}
	if c.Run.Unattended {
		hooks += "; unattended (a pause denies checks but does not stop the process)"
		if len(r.Controls) == 0 {
			fmt.Fprintln(os.Stderr, "WARNING: run.unattended without a preventive hook: a pause cannot restrain this agent; only kill decisions and the run budget stop it")
		}
	}
	fmt.Fprintf(os.Stderr, "SAGA Watchdog %s\nProject  %s\nRun      %s\nMode     %s\nBranch   %s\nPolicy   %s\nHooks    %s\nStarting %s\n", version, event.Redact(name), r.ID, c.Mode, event.Redact(g.Branch), hash[:12], hooks, event.Redact(r.Agent))
	timeout := time.NewTimer(c.Run.MaxDuration)
	defer timeout.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	stopping, childExited, postExitViolation := false, false, false
	// stopped records whether the process group is physically SIGSTOPped.
	// r.Status records the logical pause: an unattended policy pause denies
	// checks while the group keeps running, so the two can differ.
	stopped := false
	postExitFailure := ""
	rememberExitViolation := func(d policy.Decision) {
		if postExitFailure != "" {
			return
		}
		if !postExitViolation || d.Action == "kill" {
			r.Rule = d.RuleID
			r.Reason = d.Reason
		}
		postExitViolation = true
	}
	stop := func(reason, rule string) {
		if childExited {
			postExitFailure = reason
			r.Rule = rule
			r.Reason = reason
			return
		}
		if stopping {
			return
		}
		stopping = true
		r.Status = "terminating"
		r.Reason = reason
		r.Rule = rule
		r.Kills++
		fmt.Fprintf(os.Stderr, "WATCHDOG STOPPING RUN\nRule: %s\nReason: %s\n", rule, event.Redact(reason))
		if err := audit.Save(r, false); err != nil {
			fmt.Fprintln(os.Stderr, "state write failed:", event.Redact(err.Error()))
		}
		if err := process.Stop(c.Run.StopGracePeriod); err != nil {
			fmt.Fprintln(os.Stderr, "process stop:", event.Redact(err.Error()))
		}
	}
	apply := func(d policy.Decision) {
		if d.Action == "allow" {
			return
		}
		if c.Mode == "observe" {
			fmt.Fprintf(os.Stderr, "WATCHDOG OBSERVE [%s] would %s: %s\n", d.RuleID, d.Action, event.Redact(d.Reason))
			return
		}
		if d.Action == "pause" && r.Status == "paused" && !childExited {
			// Already paused: the event is recorded, no second announcement.
			return
		}
		fmt.Fprintf(os.Stderr, "WATCHDOG %s [%s] %s\n", strings.ToUpper(d.Action), d.RuleID, event.Redact(d.Reason))
		if childExited {
			if d.Action == "pause" || d.Action == "kill" {
				rememberExitViolation(d)
			}
			return
		}
		switch d.Action {
		case "pause":
			if r.Status != "paused" {
				if c.Run.Unattended {
					// No operator will resume. Leave the process group running and
					// hold the line through denied pre-action checks instead.
					fmt.Fprintln(os.Stderr, "Unattended run: process left running; every pre-action check is denied until an explicit resume")
				} else {
					if err := process.Pause(); err != nil {
						// Natural-exit cleanup can begin before Done is published. Preserve
						// the actual policy decision instead of replacing it with a control error.
						if errors.Is(err, supervisor.ErrFinished) || errors.Is(err, supervisor.ErrTerminating) {
							childExited = true
							rememberExitViolation(d)
							return
						}
						stop(err.Error(), "control-failed")
						return
					}
					stopped = true
				}
				r.Status = "paused"
				r.Pauses++
				r.Rule = d.RuleID
				r.Reason = d.Reason
				fmt.Fprintf(os.Stderr, "Resume: saga-watchdog resume %s\nKill:   saga-watchdog kill %s\n", r.ID, r.ID)
			}
		case "kill":
			stop(d.Reason, d.RuleID)
		}
	}
	handle := func(e event.Event) {
		e.Timestamp = time.Now().UTC()
		d := engine.Evaluate(e)
		if err := record(e, d); err != nil {
			stop("audit write failed: "+err.Error(), "audit-failed")
			return
		}
		apply(d)
	}
	for {
		select {
		case result := <-process.Done():
			childExited = true
			// Drain already-delivered observations before summarizing a fast child exit.
		drain:
			for {
				select {
				case e := <-queue:
					if !stopping {
						handle(e)
					}
				default:
					break drain
				}
			}
			if _, after, err := load(g.Root); err != nil || after != hash {
				if !stopping {
					handle(event.Event{Source: "supervisor", Type: "policy", Action: "tamper", Target: config.Filename, Result: "success"})
				}
			}
			for _, name := range integrations.Files() {
				// The watcher can miss a notification; the fingerprint cannot.
				if digest, ok := controlsDigest[name]; ok && !stopping && agenthook.Digest(g.Root, []string{name}) != digest {
					handle(event.Event{Source: "supervisor", Type: "file", Action: "write", Target: name, Result: "success"})
				}
			}
			status := "completed"
			code := result.ExitCode
			reason := r.Reason
			if postExitFailure != "" {
				status = "failed"
				code = 125
				reason = postExitFailure
			} else if stopping {
				status = "killed by watchdog"
				code = 125
			} else if postExitViolation {
				status = "policy violation detected at exit"
				code = 125
			} else if code != 0 {
				status = "agent failed"
				reason = "agent returned non-zero exit status"
			}
			if result.Err != nil && result.ExitCode == 0 {
				status = "failed"
				code = 125
				if reason != "" {
					reason += "; "
				}
				reason += "supervisor cleanup failed: " + result.Err.Error()
			}
			if err := record(event.Event{Source: "supervisor", Type: "process", Action: "exit", Target: r.Agent, Result: "success", Metadata: map[string]any{"exit_code": result.ExitCode}}, policy.Decision{Action: "allow", Severity: "info"}); err != nil {
				status = "failed"
				reason = "audit write failed"
				code = 125
			}
			return finish(status, reason, code)
		case e := <-queue:
			if !stopping {
				handle(e)
			}
		case err := <-failures:
			stop("observation failed: "+err.Error(), "source-failed")
		case <-timeout.C:
			record(event.Event{Source: "supervisor", Type: "process", Action: "timeout", Target: r.Agent, Result: "denied"}, policy.Decision{Action: "kill", RuleID: "max-duration", Reason: "configured run duration exceeded", Severity: "critical"})
			stop("configured maximum run duration exceeded", "max-duration")
		case sig := <-sigs:
			record(event.Event{Source: "control", Type: "process", Action: "signal", Target: sig.String(), Result: "requested"}, policy.Decision{Action: "kill", RuleID: "human-stop", Severity: "critical"})
			stop("received "+sig.String(), "human-stop")
		case <-tick.C:
			if stopping || childExited {
				continue
			}
			branch, err := gitinfo.Branch(g.Root)
			if err != nil {
				stop("cannot inspect Git branch", "git-observation-failed")
				continue
			}
			if branch != r.Branch {
				r.Branch = branch
				handle(event.Event{Source: "git", Type: "git", Action: "branch-change", Target: branch, Result: "success"})
			}
			if err = audit.Save(r, false); err != nil {
				stop("cannot persist state: "+err.Error(), "audit-failed")
			}
		case call := <-calls:
			request := call.Request
			if request.RunID != "" && request.RunID != r.ID {
				call.Reply <- socket.Response{Error: "run ID does not match this supervisor"}
				continue
			}
			if stopping || childExited {
				call.Reply <- socket.Response{Error: "run is terminating"}
				continue
			}
			switch request.Operation {
			case "status":
				snapshot := r
				call.Reply <- socket.Response{Allowed: true, Run: &snapshot}
			case "grant":
				// An operator widens this run's authority by one host or tool. The
				// grant is audited before it takes effect and never overrides a
				// deny entry.
				target := request.Event.Target
				if request.Event.Type == "network" {
					target = strings.ToLower(strings.TrimSuffix(target, "."))
				}
				if err := record(event.Event{Source: "control", Type: "process", Action: "grant", Target: request.Event.Type + " " + target, Result: "requested"}, policy.Decision{Action: "allow", Severity: "info"}); err != nil {
					call.Reply <- socket.Response{Error: "audit unavailable"}
					stop(err.Error(), "audit-failed")
					continue
				}
				if !engine.Grant(request.Event.Type, target) {
					call.Reply <- socket.Response{Error: "grant refused: unsupported target or grant limit reached"}
					continue
				}
				r.Grants = append(r.Grants, request.Event.Type+" "+target)
				snapshot := r
				call.Reply <- socket.Response{Allowed: true, Run: &snapshot}
			case "pause", "resume", "kill":
				if err := record(event.Event{Source: "control", Type: "process", Action: request.Operation, Target: r.ID, Result: "requested"}, policy.Decision{Action: "allow", Severity: "info"}); err != nil {
					call.Reply <- socket.Response{Error: "audit unavailable"}
					stop(err.Error(), "audit-failed")
					continue
				}
				var err error
				switch request.Operation {
				case "pause":
					// An explicit pause stops the group even after an unattended
					// policy pause left it running.
					if !stopped {
						err = process.Pause()
						if err == nil {
							stopped = true
							if r.Status != "paused" {
								r.Status = "paused"
								r.Pauses++
							}
						}
					}
				case "resume":
					if stopped {
						err = process.Resume()
						if err == nil {
							stopped = false
						}
					}
					if err == nil && r.Status == "paused" {
						r.Status = "running"
						r.Reason = ""
						r.Rule = ""
					}
				}
				if err != nil {
					call.Reply <- socket.Response{Error: err.Error()}
					continue
				}
				if request.Operation == "kill" {
					r.Status = "terminating"
				}
				snapshot := r
				call.Reply <- socket.Response{Allowed: true, Run: &snapshot}
				if request.Operation == "kill" {
					stop("explicit control request", "human-stop")
				}
			case "check", "emit":
				e := event.Event{Source: "integration", Type: request.Event.Type, Action: request.Event.Action, Target: request.Event.Target, Result: request.Event.Result, Timestamp: time.Now().UTC()}
				// Lineage is a producer claim kept for correlation; the source stays
				// "integration" so audit readers see the evidence class, not a name.
				for key, value := range request.Event.Lineage() {
					if e.Metadata == nil {
						e.Metadata = map[string]any{}
					}
					e.Metadata[key] = value
				}
				// A pre-action check and a post-action report can share a result
				// value; the operation keeps them apart for audit readers.
				if e.Metadata == nil {
					e.Metadata = map[string]any{}
				}
				e.Metadata["operation"] = request.Operation
				pausedCheck := r.Status == "paused" && request.Operation == "check"
				if pausedCheck {
					e.Result = "denied"
				}
				d := engine.Evaluate(e)
				if pausedCheck && d.Action != "kill" {
					d = policy.Decision{Action: "pause", RuleID: "run-paused", Reason: "run is paused; explicit resume required", Severity: "high"}
				}
				allowed := permits(c.Mode, d) && !pausedCheck
				// The decision above used the submitted path. Record an absolute
				// in-project path by its project-relative name for readability.
				if e.Type == "file" && filepath.IsAbs(e.Target) {
					if rel, err := filepath.Rel(g.Root, e.Target); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						e.Target = filepath.ToSlash(rel)
					}
				}
				if request.Operation == "check" {
					if allowed {
						e.Result = "allowed"
					} else {
						e.Result = "denied"
					}
				}
				if err := record(e, d); err != nil {
					call.Reply <- socket.Response{Error: "audit unavailable"}
					stop(err.Error(), "audit-failed")
					continue
				}
				call.Reply <- socket.Response{Allowed: allowed, Decision: &d}
				apply(d)
			}
		}
	}
}
