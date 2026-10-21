package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/integrations"
)

// coverage states what a run with this policy and these hook controls checks
// before execution, observes afterwards and cannot see at all. The doctor and
// the run banner print the same lines, so neither can claim more than the
// other. agent is the executable name a run starts, so a hook installed for
// another agent is reported as not loaded rather than as coverage; the doctor
// passes "" to describe every installed hook. contextID is the trusted
// security context, or empty with the reason correlation is off in
// disabledReason.
func coverage(c config.Config, controls []string, agent, contextID, disabledReason string) []string {
	var lines []string
	hooked := false
	for _, spec := range integrations.Specs {
		var files []string
		for _, file := range spec.Files {
			if slices.Contains(controls, file) {
				files = append(files, file)
			}
		}
		if len(files) == 0 {
			continue
		}
		if agent != "" && spec.Agent != agent {
			lines = append(lines, fmt.Sprintf("Pre-action checks: %s hook in %s is installed but not loaded by %s; it covers nothing in this run", spec.Name, strings.Join(files, ", "), agent))
			continue
		}
		hooked = true
		lines = append(lines, fmt.Sprintf("Pre-action checks: %s hook in %s for matched tools only; shell command text, MCP arguments and file reads are not interpreted", spec.Name, strings.Join(files, ", ")))
		if spec.FailClosed != "" {
			lines = append(lines, fmt.Sprintf("Hook failure: fail-closed on both sides when %s meets its contract (%s, checked by saga-watchdog %s doctor): the adapter blocks when SAGA is unreachable and the agent blocks when the hook itself cannot run", spec.Name, spec.FailClosed, spec.Agent))
		} else {
			lines = append(lines, fmt.Sprintf("Hook failure: the adapter fails closed when SAGA is unreachable, but %s lets the call proceed when the hook cannot start or times out; not fail-closed on the agent side", spec.Name))
		}
	}
	if !hooked {
		lines = append(lines, "Pre-action checks: none for "+orAny(agent)+"; without a hook or a cooperative check call nothing is prevented, only supervised and observed afterwards")
	}
	lines = append(lines,
		fmt.Sprintf("Network: cooperative checks of reported hosts (%s mode); no connection is blocked at the OS level", c.Network.Mode),
		fmt.Sprintf("Tools: cooperative checks of reported tool calls (%s mode); a tool outside a hook matcher is not seen", c.Tools.Mode),
		"File writes: checked before execution only through a hook; otherwise observed after the write, which SAGA cannot undo",
		"Credential reads: not observable; file reads are invisible and only a reporting integration can surface one",
		"Processes: only the process group SAGA started can be paused or stopped; a detached process is not contained",
		"Cross-host activity: visible only through reported events (check/emit, nested runs, Docker observer), never observed directly",
	)
	if contextID != "" {
		lines = append(lines, "Authority correlation: persistent across runs and sessions in context "+contextID)
	} else {
		lines = append(lines, "Authority correlation: this run only ("+disabledReason+")")
	}
	return lines
}

func orAny(agent string) string {
	if agent == "" {
		return "any agent"
	}
	return agent
}
