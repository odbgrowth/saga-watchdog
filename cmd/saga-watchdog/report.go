package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/integrations"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

// Report summarizes one run from its recorded state and audit log. It is a
// reading of the audit trail, not a new source of evidence.
type Report struct {
	Run      store.Run      `json:"run"`
	Duration string         `json:"duration"`
	EndedBy  string         `json:"ended_by,omitempty"`
	Counts   Counts         `json:"counts"`
	Rules    []RuleSummary  `json:"rules"`
	Denied   []DeniedCheck  `json:"denied"`
	Coverage []Coverage     `json:"coverage"`
	Warnings []string       `json:"warnings"`
	Timeline []TimelineItem `json:"timeline"`
	// Trajectory lists events that continued an earlier restriction in the
	// same security context; Instances lists agent instances this run
	// started or reported, with their provenance.
	Trajectory []TrajectoryItem `json:"trajectory"`
	Instances  []InstanceItem   `json:"instances"`
}

type TrajectoryItem struct {
	Time          time.Time `json:"time"`
	Decision      string    `json:"decision"`
	Event         string    `json:"event"`
	Correlation   string    `json:"correlation"`
	RestrictionID string    `json:"restriction_id"`
	OriginalRun   string    `json:"original_run_id"`
}

type InstanceItem struct {
	Time         time.Time `json:"time"`
	InstanceID   string    `json:"instance_id"`
	Event        string    `json:"event"`
	Host         string    `json:"host_id"`
	Decision     string    `json:"decision"`
	Provenance   string    `json:"provenance"`
	AuthorizedBy string    `json:"authorized_by_rule,omitempty"`
}

type Counts struct {
	Events   int `json:"events"`
	Checks   int `json:"checks"`
	Allowed  int `json:"allowed"`
	Denied   int `json:"denied"`
	Reports  int `json:"reports"`
	Observed int `json:"observed_changes"`
	Warnings int `json:"warnings"`
	Pauses   int `json:"pauses"`
	Kills    int `json:"kills"`
}

type RuleSummary struct {
	Rule       string `json:"rule"`
	Decision   string `json:"decision"`
	Count      int    `json:"count"`
	LastTarget string `json:"last_target"`
}

type DeniedCheck struct {
	Time     time.Time `json:"time"`
	Producer string    `json:"producer"`
	Tool     string    `json:"tool,omitempty"`
	Event    string    `json:"event"`
	Rule     string    `json:"rule"`
}

type Coverage struct {
	Producer string `json:"producer"`
	Checks   int    `json:"checks"`
	Reports  int    `json:"reports"`
}

type TimelineItem struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Rule   string    `json:"rule,omitempty"`
	Target string    `json:"target"`
}

const (
	maxDeniedRows   = 50
	maxTimelineRows = 100
	maxEventLine    = 1 << 20
)

var decisionRank = map[string]int{"warn": 1, "pause": 2, "kill": 3}

// buildReport aggregates the audit log of a run directory.
func buildReport(dir string, r store.Run) (Report, error) {
	rep := Report{Run: r}
	end := time.Now().UTC()
	if r.Finished != nil {
		end = *r.Finished
	}
	rep.Duration = end.Sub(r.Started).Round(time.Second).String()
	if r.Finished == nil {
		rep.Duration += " (still running)"
	}
	if r.Rule != "" {
		rep.EndedBy = r.Rule + ": " + r.Reason
	}
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return rep, err
	}
	defer f.Close()
	rules := map[string]*RuleSummary{}
	coverage := map[string]*Coverage{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64<<10), maxEventLine)
	for scanner.Scan() {
		var e event.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			rep.Warnings = append(rep.Warnings, "audit log contains an unreadable line")
			continue
		}
		rep.Counts.Events++
		decision, _ := e.Metadata["decision"].(string)
		if restriction, _ := e.Metadata["restriction_id"].(string); restriction != "" && len(rep.Trajectory) < maxTimelineRows {
			correlation, _ := e.Metadata["correlation"].(string)
			original, _ := e.Metadata["original_run_id"].(string)
			rep.Trajectory = append(rep.Trajectory, TrajectoryItem{Time: e.Timestamp, Decision: decision, Event: e.Type + " " + e.Action + " " + e.Target, Correlation: correlation, RestrictionID: restriction, OriginalRun: original})
		}
		if child, _ := e.Metadata["child_instance_id"].(string); child != "" && len(rep.Instances) < maxTimelineRows {
			host, _ := e.Metadata["host_id"].(string)
			provenance, _ := e.Metadata["provenance"].(string)
			by, _ := e.Metadata["authorized_by_rule"].(string)
			rep.Instances = append(rep.Instances, InstanceItem{Time: e.Timestamp, InstanceID: child, Event: e.Type + " " + e.Action + " " + e.Target, Host: host, Decision: decision, Provenance: provenance, AuthorizedBy: by})
		}
		producer, _ := e.Metadata["producer"].(string)
		tool, _ := e.Metadata["tool_name"].(string)
		switch e.Source {
		case "integration":
			if producer == "" {
				producer = "check/emit CLI"
			}
			c := coverage[producer]
			if c == nil {
				c = &Coverage{Producer: producer}
				coverage[producer] = c
			}
			// Logs written before the operation was recorded are classified by
			// the result a check produces.
			operation, _ := e.Metadata["operation"].(string)
			if operation == "" && (e.Result == "allowed" || e.Result == "denied") {
				operation = "check"
			}
			switch operation {
			case "check":
				rep.Counts.Checks++
				c.Checks++
				if e.Result == "allowed" {
					rep.Counts.Allowed++
				} else {
					rep.Counts.Denied++
					if len(rep.Denied) < maxDeniedRows {
						rep.Denied = append(rep.Denied, DeniedCheck{Time: e.Timestamp, Producer: producer, Tool: tool, Event: e.Type + " " + e.Action + " " + e.Target, Rule: e.RuleID})
					}
				}
			default:
				rep.Counts.Reports++
				c.Reports++
			}
		case "filesystem":
			rep.Counts.Observed++
		case "control":
			if len(rep.Timeline) < maxTimelineRows {
				rep.Timeline = append(rep.Timeline, TimelineItem{Time: e.Timestamp, Kind: "operator " + e.Action, Target: e.Target})
			}
		}
		if decision == "" || decision == "allow" {
			continue
		}
		if decision == "warn" {
			rep.Counts.Warnings++
		}
		if e.RuleID != "" {
			s := rules[e.RuleID]
			if s == nil {
				s = &RuleSummary{Rule: e.RuleID, Decision: decision}
				rules[e.RuleID] = s
			}
			s.Count++
			s.LastTarget = e.Target
			if decisionRank[decision] > decisionRank[s.Decision] {
				s.Decision = decision
			}
		}
		if (decision == "pause" || decision == "kill") && len(rep.Timeline) < maxTimelineRows {
			rep.Timeline = append(rep.Timeline, TimelineItem{Time: e.Timestamp, Kind: "policy " + decision, Rule: e.RuleID, Target: e.Target})
		}
	}
	if err := scanner.Err(); err != nil {
		return rep, err
	}
	rep.Counts.Pauses, rep.Counts.Kills = r.Pauses, r.Kills
	for _, s := range rules {
		rep.Rules = append(rep.Rules, *s)
	}
	sort.Slice(rep.Rules, func(i, j int) bool {
		if decisionRank[rep.Rules[i].Decision] != decisionRank[rep.Rules[j].Decision] {
			return decisionRank[rep.Rules[i].Decision] > decisionRank[rep.Rules[j].Decision]
		}
		return rep.Rules[i].Rule < rep.Rules[j].Rule
	})
	for _, c := range coverage {
		rep.Coverage = append(rep.Coverage, *c)
	}
	sort.Slice(rep.Coverage, func(i, j int) bool { return rep.Coverage[i].Producer < rep.Coverage[j].Producer })
	// A configured hook that never reported a check is the one gap the audit
	// trail can show: the agent did not run it (untrusted, disabled, off PATH)
	// or never called a matched tool.
	for _, spec := range integrations.Specs {
		for _, file := range spec.Files {
			if contains(r.Controls, file) && (coverage[spec.Producer] == nil || coverage[spec.Producer].Checks == 0) {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s carried the %s hook but no pre-action check arrived from it; the hook may be untrusted, disabled or off PATH, or no matched tool was called", file, spec.Name))
				break
			}
		}
	}
	if r.Mode == "observe" {
		rep.Warnings = append(rep.Warnings, "observe mode: denials were recorded, not enforced")
	}
	sort.SliceStable(rep.Timeline, func(i, j int) bool { return rep.Timeline[i].Time.Before(rep.Timeline[j].Time) })
	if rep.Rules == nil {
		rep.Rules = []RuleSummary{}
	}
	if rep.Denied == nil {
		rep.Denied = []DeniedCheck{}
	}
	if rep.Coverage == nil {
		rep.Coverage = []Coverage{}
	}
	if rep.Warnings == nil {
		rep.Warnings = []string{}
	}
	if rep.Trajectory == nil {
		rep.Trajectory = []TrajectoryItem{}
	}
	if rep.Instances == nil {
		rep.Instances = []InstanceItem{}
	}
	if rep.Timeline == nil {
		rep.Timeline = []TimelineItem{}
	}
	return rep, nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// writeReport renders a report for a terminal.
func writeReport(w io.Writer, rep Report) {
	r := rep.Run
	hooks := "none"
	if len(r.Controls) > 0 {
		hooks = strings.Join(r.Controls, ", ")
	}
	fmt.Fprintf(w, "SAGA Watchdog report\nRun       %s\nProject   %s\nAgent     %s\nStatus    %s\nStarted   %s\nDuration  %s\nExit      %d\nMode      %s\nBranch    %s\nPolicy    %.12s\nHooks     %s\n", r.ID, event.Redact(r.Project), event.Redact(r.Agent), r.Status, r.Started.UTC().Format(time.RFC3339), rep.Duration, r.ExitCode, r.Mode, event.Redact(r.Branch), r.PolicyHash, hooks)
	if rep.EndedBy != "" {
		fmt.Fprintf(w, "Ended by  %s\n", event.Redact(rep.EndedBy))
	}
	c := rep.Counts
	fmt.Fprintf(w, "\nCounts    events %d; checks %d (allowed %d, denied %d); reports %d; observed changes %d; warnings %d; pauses %d; kills %d\n", c.Events, c.Checks, c.Allowed, c.Denied, c.Reports, c.Observed, c.Warnings, c.Pauses, c.Kills)
	fmt.Fprintln(w, "\nDecisions by rule")
	if len(rep.Rules) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, s := range rep.Rules {
		fmt.Fprintf(w, "  %-28s %-6s %4d  last: %s\n", s.Rule, s.Decision, s.Count, event.Redact(s.LastTarget))
	}
	fmt.Fprintln(w, "\nDenied before execution")
	if len(rep.Denied) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, d := range rep.Denied {
		tool := d.Tool
		if tool == "" {
			tool = "-"
		}
		fmt.Fprintf(w, "  %s  %-14s %-16s %-40s %s\n", d.Time.UTC().Format("15:04:05"), d.Producer, tool, event.Redact(d.Event), d.Rule)
	}
	if c.Denied > len(rep.Denied) {
		fmt.Fprintf(w, "  ... %d more in events.jsonl\n", c.Denied-len(rep.Denied))
	}
	fmt.Fprintln(w, "\nPre-action coverage")
	if len(rep.Coverage) == 0 {
		fmt.Fprintln(w, "  no checks or reports; supervision and observation only")
	}
	for _, cv := range rep.Coverage {
		fmt.Fprintf(w, "  %-20s checks %4d  reports %4d\n", cv.Producer, cv.Checks, cv.Reports)
	}
	if r.Instance != nil {
		parent := ""
		if r.Instance.ParentID != "" {
			parent = ", parent " + r.Instance.ParentID
		}
		fmt.Fprintf(w, "\nInstance  %s (provenance %s%s, host %s)\n", r.Instance.ID, r.Instance.Provenance, parent, r.Instance.HostID)
	}
	if r.ContextID != "" {
		fmt.Fprintf(w, "Context   %s (%s, %s)\n", r.ContextID, r.Instance.OperatorID, r.Instance.AuthorizationContextID)
	} else if r.ContextDisabled != "" {
		fmt.Fprintf(w, "Context   none (%s)\n", r.ContextDisabled)
	}
	if len(rep.Trajectory) > 0 {
		fmt.Fprintln(w, "\nAuthority trajectory (continues earlier restrictions)")
		for _, t := range rep.Trajectory {
			fmt.Fprintf(w, "  %s  %-5s %s  [%s; restriction %s from run %s]\n", t.Time.UTC().Format("15:04:05"), t.Decision, event.Redact(t.Event), t.Correlation, t.RestrictionID, t.OriginalRun)
		}
	}
	if len(rep.Instances) > 0 {
		fmt.Fprintln(w, "\nAgent instances started or reported by this run")
		for _, i := range rep.Instances {
			by := ""
			if i.AuthorizedBy != "" {
				by = ", authorized by " + i.AuthorizedBy
			}
			fmt.Fprintf(w, "  %s  %s  %s  host %s  %s (provenance %s%s)\n", i.Time.UTC().Format("15:04:05"), i.InstanceID, event.Redact(i.Event), i.Host, i.Decision, i.Provenance, by)
		}
	}
	fmt.Fprintln(w, "\nTimeline")
	if len(rep.Timeline) == 0 {
		fmt.Fprintln(w, "  no pauses, kills or operator controls")
	}
	for _, t := range rep.Timeline {
		line := fmt.Sprintf("  %s  %-16s", t.Time.UTC().Format("15:04:05"), t.Kind)
		if t.Rule != "" {
			line += " " + t.Rule
		}
		fmt.Fprintf(w, "%s  %s\n", line, event.Redact(t.Target))
	}
	for _, warning := range rep.Warnings {
		fmt.Fprintf(w, "\nWARNING   %s\n", warning)
	}
}

// report prints the summary of one run, as text or JSON.
func report(dir string, r store.Run, asJSON bool) int {
	rep, err := buildReport(dir, r)
	if err != nil {
		return fail(err)
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fail(err)
		}
		return 0
	}
	writeReport(os.Stdout, rep)
	return 0
}
