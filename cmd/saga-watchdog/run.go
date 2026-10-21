package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/authority"
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
	// A hardened policy wants proof that the agent's own hook is in place
	// before anything starts; a run record is not written for a refusal.
	var required *agenthook.Spec
	if c.Run.RequirePreventiveHook {
		spec, err := requirePreventiveHook(g.Root, command[0])
		if err != nil {
			return fail(err)
		}
		required = spec
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	name := c.Project.Name
	if name == "" {
		name = filepath.Base(g.Root)
	}
	r := store.Run{ID: event.NewID("run"), Project: name, Agent: filepath.Base(command[0]), Status: "starting", Mode: c.Mode, Branch: g.Branch, PolicyHash: hash, Started: time.Now().UTC()}
	// A run started from inside another supervised run is a new agent
	// instance. The supervising run must authorize it, and the new instance
	// takes its identity from that trusted supervisor, never from its own
	// environment: authority does not replicate, restrictions do.
	var parent *authority.Instance
	sock, parentRun := os.Getenv("SAGA_WATCHDOG_SOCKET"), os.Getenv("SAGA_WATCHDOG_RUN_ID")
	if _, err := os.Stat(sock); sock != "" && parentRun != "" && err != nil {
		// A finished supervisor removes its socket; a leftover variable is
		// not a live parent. Removing variables is equally possible for an
		// agent, so detection is a cooperation signal, not a boundary.
		fmt.Fprintln(os.Stderr, "Ignoring stale SAGA_WATCHDOG_RUN_ID "+parentRun+": its supervisor socket no longer exists")
		sock = ""
	}
	if id := parentRun; sock != "" && id != "" {
		response, err := socket.Send(sock, socket.Request{Operation: "check", RunID: id, Event: socket.Input{Type: "agent", Action: "instance.start", Target: r.Agent, Producer: "saga-watchdog", RuntimeType: "agent"}})
		if err != nil {
			return fail(fmt.Errorf("nested run inside supervised run %s: the supervising run cannot attribute this agent instance: %w", id, err))
		}
		if !response.Allowed || response.Instance == nil {
			rule := ""
			if response.Decision != nil {
				rule = response.Decision.RuleID
			}
			return fail(fmt.Errorf("supervised run %s did not authorize another agent instance (rule %s); list it in replication.allow_agents to permit it", id, rule))
		}
		parent = response.Instance
	}
	projectID, err := store.ProjectID(g.Root)
	if err != nil {
		return fail(err)
	}
	operator, authorizationContext := os.Getenv(authority.OperatorEnv), c.SecurityContext.AuthorizationContext
	if parent != nil {
		operator, authorizationContext = parent.OperatorID, parent.AuthorizationContextID
	}
	secCtx, disabled := authority.Resolve(operator, authorizationContext, projectID, name)
	host := authority.LocalHost()
	inst := &authority.Instance{ID: authority.NewInstanceID(), PrincipalID: "agent:" + r.Agent, HostID: host.ID, RunID: r.ID, ArtifactID: authority.ArtifactID(command[0]), RuntimeType: "agent", Provenance: "unknown"}
	if parent != nil {
		inst.ID, inst.ParentID, inst.AuthorizedByRule = parent.ID, parent.ParentID, parent.AuthorizedByRule
	}
	if disabled == "" {
		inst.OperatorID, inst.ProjectID, inst.AuthorizationContextID, inst.ContextID = secCtx.OperatorID, secCtx.ProjectID, secCtx.AuthorizationContextID, secCtx.ID()
		inst.Provenance = "trusted"
		r.ContextID = secCtx.ID()
	}
	r.Instance, r.ContextDisabled = inst, disabled
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
	if required != nil && !slices.ContainsFunc(required.Files, func(file string) bool { return slices.Contains(r.Controls, file) }) {
		return finish("failed", "run.require_preventive_hook: the "+required.Name+" hook configuration changed during startup", 125)
	}
	controlsDigest := map[string]string{}
	if len(r.Controls) > 0 {
		// Once a hook is active every agent configuration file matters: a
		// sibling can disable it. Fingerprint all of them, not only the carrier.
		for _, name := range integrations.Files() {
			controlsDigest[name] = agenthook.Digest(g.Root, []string{name})
		}
	}
	var authStore *authority.Store
	if disabled == "" {
		authStore, err = authority.Open(filepath.Dir(audit.Dir), secCtx, c.SecurityContext.Retention, c.SecurityContext.SeriousRetention)
		if err != nil {
			return finish("failed", "persistent authority state: "+err.Error()+"; inspect with: saga-watchdog authority status", 125)
		}
	}
	env := make([]string, 0, len(os.Environ())+2)
	for _, v := range os.Environ() {
		// The operator identity is the operator's, not the agent's.
		if !strings.HasPrefix(v, "SAGA_WATCHDOG_SOCKET=") && !strings.HasPrefix(v, "SAGA_WATCHDOG_RUN_ID=") && !strings.HasPrefix(v, authority.OperatorEnv+"=") {
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
	// Producer claims from a configured hook adapter, or from a nested
	// saga-watchdog, are trusted-integration evidence; any other socket event
	// is self-reported. Labels never grant authority.
	// pending pairs a trusted report with the allowed check of the same
	// action, so the action counts once, and gives a start's report the
	// instance its check was given.
	pending := newPendingChecks(c.Escalation.Window, 1024)
	trustedProducers := map[string]bool{"saga-watchdog": true}
	for _, spec := range integrations.Specs {
		for _, file := range spec.Files {
			if slices.Contains(r.Controls, file) {
				trustedProducers[spec.Producer] = true
			}
		}
	}
	trustOf := func(e event.Event) string {
		switch e.Source {
		case "control":
			return "operator"
		case "integration":
			if producer, _ := e.Metadata["producer"].(string); trustedProducers[producer] {
				return "trusted-integration"
			}
			return "self-reported"
		}
		return "observed"
	}
	canonical := func(e event.Event) string {
		switch e.Type {
		case "network":
			return policy.NetworkHost(e.Target)
		case "file":
			// The form policy matched, so ./a, a and /project/a are one target.
			return engine.FileTarget(e.Target)
		}
		return e.Target
	}
	record := func(e event.Event, d policy.Decision) error {
		if e.ID == "" {
			e.ID = event.NewID("evt")
		}
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
		e.Metadata["trust"] = trustOf(e)
		e.Metadata["instance_id"] = inst.ID
		if authStore != nil {
			e.Metadata["context_id"] = secCtx.ID()
		}
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
		hooks = "preventive via " + strings.Join(r.Controls, ", ")
	}
	contextLine := secCtx.ID() + " (" + secCtx.OperatorID + ", " + secCtx.AuthorizationContextID + "); restrictions persist across runs"
	if disabled != "" {
		contextLine = "none: cross-run authority correlation disabled (" + disabled + ")"
	}
	instanceLine := inst.ID
	if inst.ParentID != "" {
		instanceLine += " (child of " + inst.ParentID + ", no inherited grants)"
	}
	if c.Run.Unattended {
		hooks += "; unattended (a pause denies checks but does not stop the process)"
		if len(r.Controls) == 0 {
			fmt.Fprintln(os.Stderr, "WARNING: run.unattended without a preventive hook: a pause cannot restrain this agent; only kill decisions and the run budget stop it")
		}
	}
	fmt.Fprintf(os.Stderr, "SAGA Watchdog %s\nProject  %s\nRun      %s\nMode     %s\nBranch   %s\nPolicy   %s\nHooks    %s\nContext  %s\nInstance %s\n", version, event.Redact(name), r.ID, c.Mode, event.Redact(g.Branch), hash[:12], hooks, event.Redact(contextLine), instanceLine)
	contextID := ""
	if disabled == "" {
		contextID = secCtx.ID()
	}
	fmt.Fprintln(os.Stderr, "Coverage")
	for _, line := range coverage(c, r.Controls, contextID, disabled) {
		fmt.Fprintln(os.Stderr, "  "+line)
	}
	fmt.Fprintf(os.Stderr, "Starting %s\n", event.Redact(r.Agent))
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
	attemptOf := func(e event.Event) authority.Attempt {
		session, _ := e.Metadata["session_id"].(string)
		hostID, _ := e.Metadata["host_id"].(string)
		if hostID == "" {
			hostID = host.ID
		}
		return authority.Attempt{Type: e.Type, Action: e.Action, Target: canonical(e), Effects: engine.Effects(e), EventID: e.ID, RunID: r.ID, InstanceID: inst.ID, SessionID: session, HostID: hostID}
	}
	// trajectory continues restrictions earned earlier in the same trusted
	// context: across runs, model sessions, agent instances and hosts. It only
	// matches observable policy facts and never infers intent.
	shadow := map[string]int{}
	trajectory := func(e *event.Event, base policy.Decision) (policy.Decision, *authority.Match) {
		if authStore == nil {
			return base, nil
		}
		// Without its authority state the run cannot know what applies: it
		// stops, and the event is denied rather than allowed.
		failed := func(reason string) (policy.Decision, *authority.Match) {
			stop(reason, "authority-state-failed")
			return policy.Decide("kill", "authority-state-failed", reason), nil
		}
		st, err := authStore.Current()
		if err != nil {
			return failed("persistent authority state unreadable: " + err.Error())
		}
		m, ok := st.Correlate(attemptOf(*e), time.Now().UTC())
		if !ok {
			return base, nil
		}
		attempts := m.Restriction.Attempts + 1
		if c.Mode != "enforce" {
			// Observe mode persists nothing; a per-run shadow count shows the
			// decisions enforce mode would take.
			shadow[m.Restriction.ID]++
			attempts = m.Restriction.Attempts + shadow[m.Restriction.ID]
		} else {
			// Count the step under the state lock: a parallel run in this
			// context gets the next number, so no threshold is skipped.
			a := attemptOf(*e)
			now := time.Now().UTC()
			n, err := authStore.Attempt(now, m.Restriction.ID, authority.Link{At: now, RunID: r.ID, EventID: e.ID, InstanceID: inst.ID, SessionID: a.SessionID, HostID: a.HostID, Type: e.Type, Target: a.Target, Correlation: m.Correlation})
			if err != nil {
				return failed("cannot persist authority state: " + err.Error())
			}
			if n == 0 {
				return base, nil // the restriction ended meanwhile
			}
			attempts = n
		}
		action := "pause"
		switch {
		case attempts >= c.Escalation.KillAfter:
			action = "kill"
		case policy.Expansion(e.Type, e.Action) && base.Authorization != "":
			// An authorized new instance in a restricted context: the
			// restrictions apply to it; it is evidence, not a violation.
			action = "warn"
		case policy.Expansion(e.Type, e.Action):
			// Unauthorized replication after a denial is the bypass itself.
			action = "kill"
		}
		reason := fmt.Sprintf("%s: continues unresolved restriction %s (%s denied %s %s in run %s at %s); attempt %d", m.Correlation, m.Restriction.ID, m.Restriction.Rule, m.Restriction.Type, m.Restriction.Target, m.Restriction.RunID, m.Restriction.Created.Format(time.RFC3339), attempts)
		if base.Action != "allow" && base.RuleID != "" {
			reason = base.RuleID + ": " + base.Reason + "; " + reason
		}
		e.Metadata["restriction_id"] = m.Restriction.ID
		e.Metadata["original_event_id"] = m.Restriction.EventID
		e.Metadata["original_run_id"] = m.Restriction.RunID
		e.Metadata["correlation"] = m.Correlation
		e.Metadata["attempts"] = attempts
		return policy.Stronger(policy.Decide(action, "authority-expansion-after-denial", reason), base), &m
	}
	// Kills from replication evidence need more than the agent's own word.
	capSelfReported := func(e event.Event, d policy.Decision) policy.Decision {
		if d.Action == "kill" && trustOf(e) == "self-reported" && (policy.ReplicationType(e.Type) || d.RuleID == "authority-expansion-after-denial") {
			d = policy.Decide("pause", d.RuleID, d.Reason+" (self-reported evidence: capped at pause)")
		}
		return d
	}
	// enforced is what a restriction records: the base rule with the
	// strongest action that took effect for the event, so an escalated kill
	// upgrades it and capped self-reported evidence does not.
	enforced := func(e event.Event, base, d policy.Decision) policy.Decision {
		if base.Escalates != "" {
			// In-run escalation replaced a concrete denial; the restriction
			// is that denial, enforced with the escalated action.
			base = policy.Decide(base.Action, base.Escalates, base.Reason)
		}
		eff := capSelfReported(e, base)
		if d.Action == "kill" && eff.Action == "pause" {
			eff.Action = "kill"
		}
		return eff
	}
	// persist records an enforced event's effect on persistent state: the
	// matched restriction upgraded to kill when a kill took effect, and a new
	// restriction for a persistable base rule.
	persist := func(e event.Event, base, d policy.Decision, m *authority.Match) {
		if authStore == nil || c.Mode != "enforce" {
			return
		}
		base = enforced(e, base, d)
		now := time.Now().UTC()
		a := attemptOf(e)
		// The step itself was counted by trajectory; a kill that took effect
		// on it upgrades the restriction.
		if m != nil && d.Action == "kill" {
			if err := authStore.Escalate(now, m.Restriction.ID, r.ID); err != nil {
				stop("cannot persist authority state: "+err.Error(), "authority-state-failed")
				return
			}
		}
		if policy.Persistable(base) {
			if err := authStore.Add(now, authority.Restriction{Rule: base.RuleID, Decision: base.Action, Type: e.Type, Target: a.Target, Effects: a.Effects, RunID: r.ID, EventID: e.ID, InstanceID: inst.ID, SessionID: a.SessionID, HostID: a.HostID}); err != nil {
				stop("cannot persist authority state: "+err.Error(), "authority-state-failed")
			}
		}
	}
	handle := func(e event.Event) {
		e.Timestamp = time.Now().UTC()
		e.ID = event.NewID("evt")
		if e.Metadata == nil {
			e.Metadata = map[string]any{}
		}
		base := engine.Evaluate(e)
		d, m := trajectory(&e, base)
		if err := record(e, d); err != nil {
			stop("audit write failed: "+err.Error(), "audit-failed")
			return
		}
		persist(e, base, d, m)
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
				// The same normalized form is granted, recorded and resolved.
				target := request.Event.Target
				if request.Event.Type == "network" {
					target = policy.NetworkHost(target)
				}
				if err := record(event.Event{Source: "control", Type: "process", Action: "grant", Target: request.Event.Type + " " + target, Result: "requested"}, policy.Decision{Action: "allow", Severity: "info"}); err != nil {
					call.Reply <- socket.Response{Error: "audit unavailable"}
					stop(err.Error(), "audit-failed")
					continue
				}
				added, ok := engine.Grant(request.Event.Type, target)
				if !ok {
					call.Reply <- socket.Response{Error: "grant refused: unsupported target or grant limit reached"}
					continue
				}
				if added {
					// Only distinct grants are persisted; the engine bounds them.
					r.Grants = append(r.Grants, request.Event.Type+" "+target)
				}
				// A grant is a trusted operator decision about this exact
				// target: it resolves the matching persistent restrictions.
				if authStore != nil && c.Mode == "enforce" {
					if _, err := authStore.Resolve(time.Now().UTC(), request.Event.Type, target, secCtx.OperatorID, "operator grant in run "+r.ID); err != nil {
						call.Reply <- socket.Response{Error: "authority state unavailable"}
						stop("cannot persist authority state: "+err.Error(), "authority-state-failed")
						continue
					}
				}
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
				e.ID = event.NewID("evt")
				creation := false
				if policy.ReplicationType(e.Type) {
					// Normalize where the runtime runs and what kind it is; both
					// are claims that can only narrow replication policy.
					hostID, remote := host.Classify(request.Event.Host)
					runtimeType := request.Event.RuntimeType
					if runtimeType == "" {
						runtimeType = "agent"
						if e.Type == "inference" {
							runtimeType = "inference-endpoint"
						}
					}
					e.Metadata["host_id"], e.Metadata["remote"], e.Metadata["runtime_type"] = hostID, remote, runtimeType
					creation = !strings.HasSuffix(e.Action, ".stop") && !strings.HasSuffix(e.Action, ".discovered") && e.Type != "remote"
				}
				// Policy weighs trust where a report would release budget.
				e.Metadata["trust"] = trustOf(e)
				pausedCheck := r.Status == "paused" && request.Operation == "check"
				if pausedCheck {
					e.Result = "denied"
				}
				// Pair a report with the allowed check of its action before
				// policy sees it: only a paired report confirms or releases
				// that check's worker reservation.
				// A report pairs only with a check that carries the same lineage:
				// one producer's, session's or agent's report never pairs with
				// another's check. Adapters send the same lineage on both.
				producer, _ := e.Metadata["producer"].(string)
				session, _ := e.Metadata["session_id"].(string)
				agentID, _ := e.Metadata["agent_id"].(string)
				callID, _ := e.Metadata["tool_use_id"].(string)
				hostKey, _ := e.Metadata["host_id"].(string)
				runtimeKey, _ := e.Metadata["runtime_type"].(string)
				// A file pairs by its lexical name: the symlink-resolved name
				// can change as a result of the action itself.
				pairTarget := canonical(e)
				if e.Type == "file" {
					pairTarget = engine.LexicalFileTarget(e.Target)
				}
				actionKey := strings.Join([]string{producer, session, agentID, e.Type, e.Action, pairTarget, callID, hostKey, runtimeKey}, "\x00")
				var prior pendingCheck
				paired := false
				if request.Operation == "emit" {
					// A start report that names its instance pairs with exactly
					// that check; without one, with the oldest of its action.
					named := ""
					if creation {
						named = request.Event.Instance
					}
					prior, paired = pending.take(actionKey, time.Now(), trustOf(e), named)
				}
				e.Metadata[policy.PairedKey] = paired
				// Worker slots are kept by instance: a start gets its instance
				// ID before policy sees it (the check's, for the report paired
				// with it), and a stop names the instance it ends.
				instanceID := ""
				switch {
				case creation && prior.instance != nil:
					instanceID = prior.instance.ID
				case creation:
					instanceID = authority.NewInstanceID()
				case e.Type == "agent" && e.Action == "instance.stop":
					instanceID = request.Event.Instance
					if instanceID != "" {
						e.Metadata["stopped_instance_id"] = instanceID
					}
				}
				e.Metadata[policy.InstanceKey] = instanceID
				base := engine.Evaluate(e)
				delete(e.Metadata, policy.PairedKey)
				delete(e.Metadata, policy.InstanceKey)
				d, match := base, (*authority.Match)(nil)
				// A hook's post-action report mirrors the check it follows;
				// correlating both would count one action twice. A trusted
				// report without a matching check (a pre-hook that failed open)
				// is the only evidence of its action and is correlated.
				mirrored := paired && trustOf(e) == "trusted-integration"
				if !mirrored {
					d, match = trajectory(&e, base)
				}
				d = capSelfReported(e, d)
				if pausedCheck && d.Action != "kill" {
					d = policy.Decision{Action: "pause", RuleID: "run-paused", Reason: "run is paused; explicit resume required", Severity: "high"}
				}
				allowed := permits(c.Mode, d) && !pausedCheck
				if !allowed {
					// A worker slot follows the final decision, not the engine's.
					engine.Release(base, instanceID)
				}
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
				// A new instance gets provenance, never authority: it starts with
				// no grants, and only a Watchdog-supervised child in a complete
				// trusted context is "trusted".
				var child *authority.Instance
				if creation {
					hostID, _ := e.Metadata["host_id"].(string)
					remote, _ := e.Metadata["remote"].(bool)
					runtimeType, _ := e.Metadata["runtime_type"].(string)
					// The report of a start names the instance its check was
					// given: one start is one instance. A later check is a new
					// start and gets a new instance.
					child = prior.instance
					if child == nil {
						child = &authority.Instance{ID: instanceID, ParentID: inst.ID, PrincipalID: "agent:" + e.Target, HostID: hostID, RuntimeType: runtimeType, Provenance: "unknown"}
						if allowed {
							child.AuthorizedByRule = base.Authorization
							if authStore != nil {
								child.OperatorID, child.ProjectID, child.AuthorizationContextID, child.ContextID = secCtx.OperatorID, secCtx.ProjectID, secCtx.AuthorizationContextID, secCtx.ID()
							}
							if authStore != nil && !remote && trustOf(e) == "trusted-integration" && e.Metadata["producer"] == "saga-watchdog" {
								child.Provenance = "trusted"
							}
						}
					}
				}
				// Only an allowed check is followed by a report of its action.
				if request.Operation == "check" && allowed {
					pending.add(actionKey, time.Now(), trustOf(e), child, base.Reserved)
				}
				if child != nil {
					e.Metadata["child_instance_id"], e.Metadata["provenance"], e.Metadata["authorized_by_rule"] = child.ID, child.Provenance, child.AuthorizedByRule
				}
				if err := record(e, d); err != nil {
					call.Reply <- socket.Response{Error: "audit unavailable"}
					stop(err.Error(), "audit-failed")
					continue
				}
				persist(e, base, d, match)
				response := socket.Response{Allowed: allowed, Decision: &d}
				if allowed && child != nil {
					response.Instance = child
				}
				call.Reply <- response
				apply(d)
			}
		}
	}
}

// requirePreventiveHook identifies the supported agent a command starts and
// verifies that agent's own hook, not merely any installed hook. It reuses
// the agent doctor's checks and refuses with every failed one. A command
// without a supported integration cannot be verified and is refused rather
// than declared protected.
func requirePreventiveHook(root, executable string) (*agenthook.Spec, error) {
	spec := integrations.ForAgent(executable)
	if spec == nil {
		var agents []string
		for _, s := range integrations.Specs {
			agents = append(agents, s.Agent)
		}
		return nil, fmt.Errorf("run.require_preventive_hook: preventive integration cannot be verified for %q; supported agents are %s. A generic command is supervised and observed after the fact only: start a supported agent, or set run.require_preventive_hook: false to run without pre-action coverage", filepath.Base(executable), strings.Join(agents, ", "))
	}
	if problems := hookReadiness(spec, root).problems(); len(problems) > 0 {
		return nil, fmt.Errorf("run.require_preventive_hook: the %s preventive hook is not ready for %q:\n  - %s\nFix the items above (saga-watchdog %s doctor), or set run.require_preventive_hook: false", spec.Name, filepath.Base(executable), strings.Join(problems, "\n  - "), spec.Agent)
	}
	return spec, nil
}
