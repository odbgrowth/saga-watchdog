//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

const authorityPolicy = "version: 1\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\nsecurity_context:\n  authorization_context: dev-local\nnetwork:\n  deny: [deploy.example.com]\neffects:\n  production.deploy: ['network:deploy.example.com', 'tool:vercel/*']\n"

// endRun kills a live run and waits for it.
func endRun(t *testing.T, done chan error, out interface{ String() string }, send func(string, socket.Input) socket.Response) {
	t.Helper()
	send("kill", socket.Input{})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("run did not stop: %s", out.String())
	}
}

func runCLI(t *testing.T, root string, env []string, args ...string) (int, string) {
	t.Helper()
	cmd, out := cliCommand(t, root, args...)
	cmd.Env = append(cmd.Env, env...)
	return exitCode(cmd.Run()), out.String()
}

// Tests 1, 2, 4, 5, 6: one trajectory across runs and model sessions within a
// trusted context, and no correlation across operators, authorization
// contexts or projects.
func TestAuthorityHistorySurvivesRunsAndSessions(t *testing.T) {
	root := fixture(t, authorityPolicy)
	state := os.Getenv("SAGA_WATCHDOG_STATE_DIR")
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")

	runA, doneA, outA, sendA := liveRun(t, root, "sleep 15")
	if d := sendA("check", socket.Input{Type: "network", Action: "connect", Target: "https://deploy.example.com/v1", SessionID: "sess-1"}); d.Allowed || d.Decision.RuleID != "network-denied" {
		t.Fatalf("run A denial: %+v", d.Decision)
	}
	endRun(t, doneA, outA, sendA)

	// A new run and a new model session reach the same effect by another tool.
	runB, doneB, outB, sendB := liveRun(t, root, "sleep 15")
	d := sendB("check", socket.Input{Type: "tool", Action: "call", Target: "vercel/deploy", SessionID: "sess-2"})
	if d.Allowed || d.Decision.RuleID != "authority-expansion-after-denial" || d.Decision.Action != "pause" || !strings.Contains(d.Decision.Reason, runA.ID) || !strings.Contains(d.Decision.Reason, "alternate route to effect production.deploy") {
		t.Fatalf("run B alternate route: %+v", d.Decision)
	}
	sendB("resume", socket.Input{})
	if d := sendB("check", socket.Input{Type: "network", Action: "connect", Target: "pypi.org", SessionID: "sess-2"}); !d.Allowed || d.Decision.RuleID != "" {
		t.Fatalf("unrelated download correlated: %+v", d.Decision)
	}
	endRun(t, doneB, outB, sendB)
	if code, text := runCLI(t, root, nil, "authority", "status"); code != 0 || !strings.Contains(text, "network-denied") || !strings.Contains(text, "attempts 2") || !strings.Contains(text, "session sess-2") || !strings.Contains(text, runB.ID) {
		t.Fatalf("authority status %d: %s", code, text)
	}
	if code, text := runCLI(t, root, nil, "report", "--run", runB.ID); code != 0 || !strings.Contains(text, "Authority trajectory") || !strings.Contains(text, runA.ID) {
		t.Fatalf("report %d: %s", code, text)
	}
	events, _ := readEvents(t, root, runB.ID)
	if e := find(events, "integration", "tool", "vercel/deploy"); e == nil || e.Metadata["original_run_id"] != runA.ID || e.Metadata["session_id"] != "sess-2" || e.Metadata["context_id"] == nil || e.Metadata["trust"] != "self-reported" {
		t.Fatalf("trajectory audit: %+v", e)
	}

	allowedWithout := func(label string) {
		t.Helper()
		_, done, out, send := liveRun(t, root, "sleep 15")
		if d := send("check", socket.Input{Type: "tool", Action: "call", Target: "vercel/deploy"}); !d.Allowed {
			t.Fatalf("%s: correlated across contexts: %+v", label, d.Decision)
		}
		endRun(t, done, out, send)
	}
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:other")
	allowedWithout("different operator")
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	if err := os.WriteFile(filepath.Join(root, ".saga-watchdog.yaml"), []byte(strings.Replace(authorityPolicy, "dev-local", "production-readonly", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	allowedWithout("different authorization context")
	other := fixture(t, authorityPolicy)
	t.Setenv("SAGA_WATCHDOG_STATE_DIR", state)
	root = other
	allowedWithout("different project")
	// Without operator identity there is no persistence, and the run says so.
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "")
	if code, text := runCLI(t, root, nil, "doctor"); code != 0 || !strings.Contains(text, "! cross-run authority correlation disabled: operator identity unavailable") {
		t.Fatalf("doctor %d: %s", code, text)
	}
}

// Tests 9 and 10: an agent cannot clear its own history; an operator can, and
// the clear is audited.
func TestOnlyOperatorsClearAuthorityHistory(t *testing.T) {
	root := fixture(t, authorityPolicy)
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	r, done, out, send := liveRun(t, root, "sleep 15")
	send("check", socket.Input{Type: "network", Action: "connect", Target: "deploy.example.com"})
	send("resume", socket.Input{})
	inside := []string{"SAGA_WATCHDOG_RUN_ID=" + r.ID, "SAGA_WATCHDOG_SOCKET=" + r.Socket}
	if code, text := runCLI(t, root, inside, "authority", "clear", "--all", "--reason", "the agent says it is approved"); code != 2 || !strings.Contains(text, "refused") {
		t.Fatalf("agent clear %d: %s", code, text)
	}
	if status := send("status", socket.Input{}); status.Run.Status != "paused" || status.Run.Rule != "authority-self-clear" {
		t.Fatalf("self-clear not reported: %+v", status.Run)
	}
	endRun(t, done, out, send)
	if code, text := runCLI(t, root, nil, "authority", "status"); code != 0 || !strings.Contains(text, "network-denied") || !strings.Contains(text, "authority-self-clear") {
		t.Fatalf("history changed by the agent %d: %s", code, text)
	}
	if code, text := runCLI(t, root, []string{"SAGA_WATCHDOG_OPERATOR="}, "authority", "clear", "--all", "--reason", "x"); code != 2 || !strings.Contains(text, "operator identity unavailable") {
		t.Fatalf("clear without operator %d: %s", code, text)
	}
	if code, text := runCLI(t, root, nil, "authority", "clear", "--all", "--reason", "reviewed with the team"); code != 0 || strings.Count(text, "Cleared ") != 2 || !strings.Contains(text, "by human:onno") {
		t.Fatalf("operator clear %d: %s", code, text)
	}
	if code, text := runCLI(t, root, nil, "authority", "status"); code != 0 || !strings.Contains(text, "No unresolved restrictions") {
		t.Fatalf("after clear %d: %s", code, text)
	}
	if code, text := runCLI(t, root, nil, "authority", "history"); code != 0 || !strings.Contains(text, `"action":"cleared"`) || !strings.Contains(text, `"who":"human:onno"`) || !strings.Contains(text, "reviewed with the team") {
		t.Fatalf("clear not audited %d: %s", code, text)
	}
}

// Tests 3, 18, 19, 20: an authorized child agent gets provenance and the
// parent's restrictions, but none of its grants.
func TestNestedAgentInheritsRestrictionsNotAuthority(t *testing.T) {
	policy := "version: 1\nmode: enforce\nrun:\n  max_duration: 25s\n  stop_grace_period: 50ms\nsecurity_context:\n  authorization_context: dev-local\nnetwork:\n  mode: allowlist\n  allow: [allowed.example]\n  deny: [deploy.example.com]\nreplication:\n  allow_agents: [sh]\n"
	root := fixture(t, policy)
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	t.Setenv("SAGA_TEST_BIN", os.Args[0])
	script := `while [ ! -f go ]; do sleep 0.05; done
"$SAGA_TEST_BIN" -test.run='^TestCLIHelper$' -- run -- sh -c 'printf "%s" "$SAGA_WATCHDOG_RUN_ID" > child.id; while [ ! -f done ]; do sleep 0.05; done' 2> nested.err
echo "nested=$?" > nested.code
while [ ! -f finish ]; do sleep 0.05; done`
	parent, done, out, send := liveRun(t, root, script)
	if d := send("check", socket.Input{Type: "network", Action: "connect", Target: "deploy.example.com"}); d.Allowed {
		t.Fatal("parent denial expected")
	}
	send("resume", socket.Input{})
	if d := send("grant", socket.Input{Type: "network", Target: "granted.example"}); d.Run == nil || len(d.Run.Grants) != 1 {
		t.Fatalf("parent grant: %+v", d)
	}
	if err := os.WriteFile(filepath.Join(root, "go"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var childID string
	for deadline := time.Now().Add(10 * time.Second); childID == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		data, _ := os.ReadFile(filepath.Join(root, "child.id"))
		childID = string(data)
	}
	if childID == "" {
		errs, _ := os.ReadFile(filepath.Join(root, "nested.err"))
		t.Fatalf("nested run did not start: %s %s", errs, out)
	}
	// The child's command can run before its supervisor persists the socket
	// paths; wait for the record that carries them.
	var child store.Run
	for deadline := time.Now().Add(5 * time.Second); child.Socket == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, found, err := store.Locate(root, childID); err == nil {
			child = found
		}
	}
	if child.Socket == "" {
		t.Fatalf("child run record never carried its sockets: %s", out)
	}
	if child.Instance == nil || child.Instance.ParentID == "" || child.Instance.Provenance != "trusted" || child.Instance.AuthorizedByRule != "replication.allow_agents" || child.ContextID == "" || child.Instance.OperatorID != "human:onno" {
		t.Fatalf("child provenance: %+v %+v", child.Instance, child)
	}
	sendChild := func(op string, input socket.Input) socket.Response {
		path := child.Socket
		if op != "check" {
			path = child.Control
		}
		response, err := socket.Send(path, socket.Request{Operation: op, RunID: child.ID, Event: input})
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	// Restrictions propagate: the child retries the parent's denied target.
	if d := sendChild("check", socket.Input{Type: "network", Action: "connect", Target: "deploy.example.com"}); d.Allowed || d.Decision.RuleID != "authority-expansion-after-denial" || !strings.Contains(d.Decision.Reason, parent.ID) {
		t.Fatalf("child retry: %+v", d.Decision)
	}
	sendChild("resume", socket.Input{})
	// Authority does not: the parent's grant is not the child's.
	if d := sendChild("check", socket.Input{Type: "network", Action: "connect", Target: "granted.example"}); d.Allowed || d.Decision.RuleID != "network-unlisted" {
		t.Fatalf("child inherited a grant: %+v", d.Decision)
	}
	sendChild("kill", socket.Input{})
	os.WriteFile(filepath.Join(root, "done"), nil, 0600)
	var code string
	for deadline := time.Now().Add(10 * time.Second); code == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		data, _ := os.ReadFile(filepath.Join(root, "nested.code"))
		code = strings.TrimSpace(string(data))
	}
	if code != "nested=125" {
		t.Fatalf("nested exit %q", code)
	}
	events, _ := readEvents(t, root, parent.ID)
	start := find(events, "integration", "agent", "sh")
	if start == nil || start.Metadata["child_instance_id"] != child.Instance.ID || start.Metadata["trust"] != "trusted-integration" || start.Metadata["provenance"] != "trusted" {
		t.Fatalf("parent audit of the child: %+v", start)
	}
	os.WriteFile(filepath.Join(root, "finish"), nil, 0600)
	endRun(t, done, out, send)
}

// An agent that starts another supervised agent without authorization is
// refused, and the supervising run pauses.
func TestUnauthorizedNestedAgentIsRefused(t *testing.T) {
	root := fixture(t, "version: 1\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\n")
	t.Setenv("SAGA_TEST_BIN", os.Args[0])
	script := `"$SAGA_TEST_BIN" -test.run='^TestCLIHelper$' -- run -- sh -c 'echo started > child.ran' 2> nested.err
echo "nested=$?" > nested.code
sleep 15`
	_, done, out, send := liveRun(t, root, script)
	var status socket.Response
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if status = send("status", socket.Input{}); status.Run.Status == "paused" {
			break
		}
	}
	if status.Run.Rule != "unauthorized-agent-replication" {
		t.Fatalf("parent not paused for replication: %+v", status.Run)
	}
	send("resume", socket.Input{})
	var code string
	for deadline := time.Now().Add(10 * time.Second); code == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		data, _ := os.ReadFile(filepath.Join(root, "nested.code"))
		code = strings.TrimSpace(string(data))
	}
	errs, _ := os.ReadFile(filepath.Join(root, "nested.err"))
	if code != "nested=2" || !strings.Contains(string(errs), "did not authorize another agent instance") {
		t.Fatalf("nested run not refused: %q %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(root, "child.ran")); err == nil {
		t.Fatal("unauthorized child agent ran")
	}
	endRun(t, done, out, send)
}

// Tests 11-17, 21 and trust levels through a live supervisor.
func TestReplicationEvidenceTrustAndProvenance(t *testing.T) {
	root := fixture(t, "version: 1\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\nreplication:\n  same_host_workers: 1\n  inference_endpoints: ['127.0.0.1:8000']\n")
	r, done, out, send := liveRun(t, root, "for i in 1 2 3; do sh -c true; done; sleep 15")
	check := func(input socket.Input) socket.Response {
		t.Helper()
		d := send("check", input)
		if !d.Allowed {
			send("resume", socket.Input{})
		}
		return d
	}
	worker := check(socket.Input{Type: "agent", Action: "instance.start", Target: "test-runner", RuntimeType: "worker"})
	if !worker.Allowed || worker.Decision.Authorization != "replication.same_host_workers" || worker.Instance == nil || worker.Instance.Provenance != "unknown" {
		t.Fatalf("authorized worker: %+v %+v", worker.Decision, worker.Instance)
	}
	// The report of that start is the same worker: same slot, same instance.
	if d := send("emit", socket.Input{Type: "agent", Action: "instance.start", Target: "test-runner", RuntimeType: "worker", Result: "success"}); !d.Allowed {
		t.Fatalf("report of the authorized worker: %+v", d.Decision)
	}
	if d := check(socket.Input{Type: "agent", Action: "instance.start", Target: "codex"}); d.Allowed || d.Decision.RuleID != "unauthorized-agent-replication" || d.Decision.Action != "pause" || d.Instance != nil {
		t.Fatalf("unauthorized agent: %+v", d.Decision)
	}
	if d := check(socket.Input{Type: "inference", Action: "endpoint.start", Target: "0.0.0.0:8000"}); d.Allowed || d.Decision.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("model server: %+v", d.Decision)
	}
	if d := check(socket.Input{Type: "network", Action: "connect", Target: "build-02"}); !d.Allowed || strings.Contains(d.Decision.RuleID, "replication") || strings.Contains(d.Decision.RuleID, "cross-host") {
		t.Fatalf("remote connection only: %+v", d.Decision)
	}
	// Self-reported cross-host evidence pauses; it cannot kill on its own.
	if d := check(socket.Input{Type: "runtime", Action: "start", Target: "codex", Host: "build-02"}); d.Allowed || d.Decision.RuleID != "cross-host-authority-expansion" || d.Decision.Action != "pause" || !strings.Contains(d.Decision.Reason, "self-reported") {
		t.Fatalf("self-reported cross-host: %+v", d.Decision)
	}
	// The same evidence from a trusted integration stops the source run.
	if d := send("check", socket.Input{Type: "runtime", Action: "start", Target: "codex", Host: "build-02", Producer: "saga-watchdog"}); d.Allowed || d.Decision.Action != "kill" || d.Decision.RuleID != "cross-host-authority-expansion" {
		t.Fatalf("trusted cross-host: %+v", d.Decision)
	}
	select {
	case err := <-done:
		if exitCode(err) != 125 {
			t.Fatalf("exit %v: %s", err, out)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("cross-host kill did not stop the run: %s", out)
	}
	events, _ := readEvents(t, root, r.ID)
	trust := map[string]string{}
	for _, e := range events {
		trust[e.Source+"/"+e.Action], _ = e.Metadata["trust"].(string)
	}
	for key, want := range map[string]string{"supervisor/start": "observed", "control/resume": "operator", "integration/instance.start": "self-reported"} {
		if trust[key] != want {
			t.Errorf("%s trust %q, want %s (%v)", key, trust[key], want, trust)
		}
	}
	if e := find(events, "integration", "agent", "test-runner"); e == nil || e.Metadata["provenance"] != "unknown" || e.Metadata["authorized_by_rule"] != "replication.same_host_workers" || e.Metadata["instance_id"] != r.Instance.ID {
		t.Fatalf("worker provenance audit: %+v", e)
	}
	var children []any
	for _, e := range events {
		if e.Type == "agent" && e.Target == "test-runner" {
			children = append(children, e.Metadata["child_instance_id"])
		}
	}
	if len(children) != 2 || children[0] != worker.Instance.ID || children[1] != worker.Instance.ID {
		t.Fatalf("check and report of one start name different instances: %v (assigned %s)", children, worker.Instance.ID)
	}
	var violations int
	for _, e := range events {
		if e.Source == "supervisor" && e.Type == "process" && e.Metadata["decision"] != "allow" && e.Action != "exit" {
			violations++
		}
	}
	if violations != 0 {
		t.Fatalf("ordinary subprocesses were flagged: %d", violations)
	}
}

// A restriction from self-reported replication evidence carries the capped
// decision that took effect, and its pause-level retention.
func TestSelfReportedReplicationPersistsCappedDecision(t *testing.T) {
	root := fixture(t, authorityPolicy)
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	_, done, out, send := liveRun(t, root, "sleep 15")
	if d := send("check", socket.Input{Type: "runtime", Action: "start", Target: "codex", Host: "build-02"}); d.Allowed || d.Decision.Action != "pause" || d.Decision.RuleID != "cross-host-authority-expansion" {
		t.Fatalf("self-reported cross-host: %+v", d.Decision)
	}
	endRun(t, done, out, send)
	code, text := runCLI(t, root, nil, "authority", "status")
	if code != 0 || !strings.Contains(text, "cross-host-authority-expansion") {
		t.Fatalf("authority status %d: %s", code, text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "cross-host-authority-expansion") && !strings.Contains(line, " pause ") {
			t.Fatalf("persisted the uncapped decision: %s", line)
		}
	}
}

// A trusted report is skipped by correlation only when it mirrors an allowed
// check of the same action; a report whose pre-hook failed open is
// correlated, also after a denied check of the same target. A denial
// escalated to kill persists as a kill restriction.
func TestTrustedReportsAndEscalatedKillsPersist(t *testing.T) {
	root := fixture(t, authorityPolicy+"replication:\n  allow_agents: [claude]\ntools:\n  deny: ['payments/*']\n")
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	deploy := socket.Input{Type: "network", Action: "connect", Target: "deploy.example.com", Producer: "saga-watchdog"}

	_, doneA, outA, sendA := liveRun(t, root, "sleep 15")
	if d := sendA("check", deploy); d.Allowed {
		t.Fatalf("run A denial: %+v", d.Decision)
	}
	endRun(t, doneA, outA, sendA)

	// A denied check is followed by no report, so a later report of the same
	// target (no call ID, as from Gemini) is an unpaired action.
	_, doneB, outB, sendB := liveRun(t, root, "sleep 15")
	if d := sendB("check", deploy); d.Allowed {
		t.Fatalf("run B denial: %+v", d.Decision)
	}
	sendB("resume", socket.Input{})
	report := deploy
	report.Result = "success"
	if d := sendB("emit", report); d.Decision == nil || d.Decision.RuleID != "authority-expansion-after-denial" {
		t.Fatalf("unpaired trusted report not correlated: %+v", d.Decision)
	}
	endRun(t, doneB, outB, sendB)

	// An allowed, correlated check and its report count once.
	_, doneP, outP, sendP := liveRun(t, root, "sleep 15")
	agent := socket.Input{Type: "agent", Action: "instance.start", Target: "claude", Producer: "saga-watchdog", CallID: "call-1"}
	if d := sendP("check", agent); !d.Allowed || d.Decision.RuleID != "authority-expansion-after-denial" {
		t.Fatalf("authorized agent in a restricted context: %+v", d.Decision)
	}
	agent.Result = "success"
	sendP("emit", agent)
	endRun(t, doneP, outP, sendP)
	if code, text := runCLI(t, root, nil, "authority", "status"); code != 0 || !strings.Contains(text, "attempts 4") {
		t.Fatalf("want one attempt per action (denial, denied check, unpaired report, paired check): %d %s", code, text)
	}

	// A correlated attempt that base policy allows reaches kill_after across
	// runs: the matched restriction itself becomes a kill restriction.
	_, doneC, outC, sendC := liveRun(t, root, "sleep 15")
	if d := sendC("check", socket.Input{Type: "tool", Action: "call", Target: "vercel/deploy", Producer: "saga-watchdog"}); d.Decision.Action != "kill" || d.Decision.RuleID != "authority-expansion-after-denial" {
		t.Fatalf("fifth attempt across runs: %+v", d.Decision)
	}
	waitDone := func(done chan error, out interface{ String() string }) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("kill did not stop the run: %s", out.String())
		}
	}
	waitDone(doneC, outC)
	// Repeated denials of a new target escalate to kill within one run; the
	// new restriction records the kill.
	_, doneD, outD, sendD := liveRun(t, root, "sleep 15")
	var last socket.Response
	for range 5 {
		last = sendD("check", socket.Input{Type: "tool", Action: "call", Target: "payments/charge", Producer: "saga-watchdog"})
		if last.Decision != nil && last.Decision.Action == "kill" {
			break
		}
	}
	if last.Decision == nil || last.Decision.Action != "kill" || last.Decision.RuleID != "failure-escalation" {
		t.Fatalf("no in-run escalation to kill: %+v", last.Decision)
	}
	waitDone(doneD, outD)
	code, text := runCLI(t, root, nil, "authority", "status")
	if code != 0 {
		t.Fatalf("authority status %d: %s", code, text)
	}
	for _, rule := range []string{"network-denied", "tool-denied"} {
		found := false
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, rule) {
				found = true
				if !strings.Contains(line, " kill ") {
					t.Fatalf("enforced kill persisted as %s", line)
				}
			}
		}
		if !found {
			t.Fatalf("no %s restriction: %s", rule, text)
		}
	}
}

// Concurrent starts of one agent keep their own instances: by call ID, or in
// order for producers without one.
func TestConcurrentStartsKeepTheirInstances(t *testing.T) {
	root := fixture(t, "version: 1\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\nreplication:\n  allow_agents: [claude]\n")
	r, done, out, send := liveRun(t, root, "sleep 15")
	start := func(call string) socket.Input {
		return socket.Input{Type: "agent", Action: "instance.start", Target: "claude", Producer: "saga-watchdog", CallID: call}
	}
	assigned := map[string]string{}
	for _, call := range []string{"call-1", "call-2", "", ""} {
		d := send("check", start(call))
		if !d.Allowed || d.Instance == nil {
			t.Fatalf("check %q: %+v", call, d.Decision)
		}
		if call == "" {
			call = "anon-" + string(rune('a'+len(assigned)-2))
		}
		assigned[call] = d.Instance.ID
	}
	for _, call := range []string{"call-2", "call-1", "", ""} {
		report := start(call)
		report.Result = "success"
		send("emit", report)
	}
	endRun(t, done, out, send)
	events, _ := readEvents(t, root, r.ID)
	var reports []map[string]any
	for _, e := range events {
		if e.Type == "agent" && e.Metadata["operation"] == "emit" {
			reports = append(reports, e.Metadata)
		}
	}
	want := []string{assigned["call-2"], assigned["call-1"], assigned["anon-a"], assigned["anon-b"]}
	if len(reports) != 4 {
		t.Fatalf("reports: %v", reports)
	}
	for i, m := range reports {
		if m["child_instance_id"] != want[i] {
			t.Fatalf("report %d named %v, its check was given %s", i, m["child_instance_id"], want[i])
		}
	}
}

// A check pairs with its report only within the escalation window; a report
// after that counts as its own action.
func TestReportPairsExpireAfterTheWindow(t *testing.T) {
	root := fixture(t, authorityPolicy+"replication:\n  allow_agents: [claude]\nescalation:\n  window: 1s\n  kill_after: 10\n")
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	_, doneA, outA, sendA := liveRun(t, root, "sleep 15")
	sendA("check", socket.Input{Type: "network", Action: "connect", Target: "deploy.example.com"})
	endRun(t, doneA, outA, sendA)

	_, doneB, outB, sendB := liveRun(t, root, "sleep 15")
	agent := socket.Input{Type: "agent", Action: "instance.start", Target: "claude", Producer: "saga-watchdog"}
	// Two concurrent starts without call IDs (as from Gemini): each report
	// pairs with one check, so neither counts again.
	for range 2 {
		if d := sendB("check", agent); !d.Allowed || d.Decision.RuleID != "authority-expansion-after-denial" {
			t.Fatalf("authorized agent in a restricted context: %+v", d.Decision)
		}
	}
	report := agent
	report.Result = "success"
	for range 2 {
		if d := sendB("emit", report); d.Decision == nil || d.Decision.RuleID == "authority-expansion-after-denial" {
			t.Fatalf("paired report counted again: %+v", d.Decision)
		}
	}
	// A check whose report comes after the window pairs with nothing.
	sendB("check", agent)
	time.Sleep(1200 * time.Millisecond)
	if d := sendB("emit", report); d.Decision == nil || d.Decision.RuleID != "authority-expansion-after-denial" {
		t.Fatalf("report after the window not correlated: %+v", d.Decision)
	}
	endRun(t, doneB, outB, sendB)
	if code, text := runCLI(t, root, nil, "authority", "status"); code != 0 || !strings.Contains(text, "attempts 5") {
		t.Fatalf("want the denial, three checks and the late report: %d %s", code, text)
	}
}
