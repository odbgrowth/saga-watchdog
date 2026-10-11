// Package codex adapts Codex CLI hook events to canonical SAGA events. Codex
// implements the Claude Code hook contract (PreToolUse and PostToolUse on
// stdin, exit code 2 blocks with stderr as the reason); what differs is the
// tool vocabulary and the .codex/hooks.json file. Verified against Codex CLI
// 0.162.1 source: codex-rs/hooks and codex-rs/core/src/tools/hook_names.rs.
package codex

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
)

const (
	// Producer identifies this adapter in audit metadata.
	Producer = "codex"
	// Command is the shell-form hook command written into .codex/hooks.json.
	Command = "saga-watchdog codex hook"
	// Matcher is a regular expression: Codex treats any pattern with characters
	// outside letters, digits, underscore and "|" as one. Bash is the name of
	// every shell-like tool, apply_patch of every file edit, spawn_agent of
	// sub-agent creation and mcp__ of every MCP tool. Hosted tools such as web
	// search never reach a hook.
	Matcher = "^(Bash|apply_patch|spawn_agent|mcp__.*)$"
	// maxPatchFiles bounds the checks one apply_patch call can trigger.
	maxPatchFiles = 256
)

// Files are the project-scoped Codex files that carry the SAGA hook. The user
// level ~/.codex and the inline [hooks] table of .codex/config.toml are not
// written by SAGA; config.toml is still watched as agent configuration.
var Files = []string{".codex/hooks.json"}

// Spec is the Codex CLI hook configuration.
var Spec = agenthook.Spec{
	Name: "Codex CLI", Agent: "codex", Producer: Producer, Command: Command, Matcher: Matcher, PreEvent: "PreToolUse", Files: Files,
	Hooks: hooks,
	// A background (async) hook cannot block, so it is not preventive.
	Preventive: func(_, hook map[string]any) bool { return hook["async"] != true },
}

// hooks returns the hook groups SAGA installs. Codex has no onFailure
// option: an adapter that cannot start or times out is reported as a failed
// hook and the call proceeds, so the adapter must exist on PATH; saga-watchdog
// codex doctor checks that. The timeout is in seconds.
func hooks() map[string]any {
	group := func() []any {
		return []any{map[string]any{"matcher": Matcher, "hooks": []any{map[string]any{"type": "command", "command": Command, "timeout": 10, "statusMessage": "SAGA Watchdog check"}}}}
	}
	return map[string]any{"PreToolUse": group(), "PostToolUse": group()}
}

// Input holds the documented hook fields SAGA reads. tool_input is decoded
// only for apply_patch, and then only its file headers are kept.
type Input struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	AgentID       string          `json:"agent_id"`
	AgentType     string          `json:"agent_type"`
	Cwd           string          `json:"cwd"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolUseID     string          `json:"tool_use_id"`
}

type toolFields struct {
	Command string `json:"command"`
}

// Normalize maps one hook event to the socket requests it implies. An empty
// result means the event is not evaluated. The error text never contains tool
// arguments.
func Normalize(in Input) ([]socket.Request, error) {
	var op, result string
	switch in.HookEventName {
	case "PreToolUse":
		op = "check"
	case "PostToolUse":
		// Codex fires PostToolUse only for a tool that produced output.
		op, result = "emit", "success"
	default:
		return nil, nil
	}
	tool := agenthook.Identifier(in.ToolName)
	if tool == "" {
		return nil, errors.New("hook input has no tool name")
	}
	base := socket.Input{Result: result, Producer: Producer, Tool: tool, AgentID: agenthook.Identifier(in.AgentID), AgentType: agenthook.Identifier(in.AgentType), CallID: agenthook.Identifier(in.ToolUseID), SessionID: agenthook.Identifier(in.SessionID)}
	var events []socket.Input
	switch in.ToolName {
	case "apply_patch":
		var fields toolFields
		if len(in.ToolInput) > 0 {
			if err := json.Unmarshal(in.ToolInput, &fields); err != nil {
				return nil, errors.New("tool_input is not a JSON object")
			}
		}
		// Only the file headers of the patch are read; hunk content is never
		// retained. Each named file is checked on its own, so one patch that
		// touches a protected path is blocked as a whole.
		targets := patchTargets(fields.Command)
		if len(targets) == 0 {
			return nil, errors.New("apply_patch input names no file")
		}
		if len(targets) > maxPatchFiles {
			return nil, errors.New("apply_patch names too many files")
		}
		for _, t := range targets {
			e := base
			e.Type, e.Action, e.Target = "file", t.action, resolve(in.Cwd, t.path)
			events = append(events, e)
		}
	case "Bash":
		// SAGA is not a shell interpreter: the command text is never read.
		e := base
		e.Type, e.Action, e.Target = "process", "execute", tool
		events = append(events, e)
	default:
		e := base
		e.Type, e.Action, e.Target = "tool", "call", tool
		if target, ok := agenthook.MCPTarget(in.ToolName, "mcp__", "__"); ok {
			e.Target = target
		}
		events = append(events, e)
	}
	requests := make([]socket.Request, 0, len(events))
	for _, e := range events {
		requests = append(requests, socket.Request{Operation: op, Event: e})
	}
	return requests, nil
}

type patchTarget struct{ action, path string }

var patchHeaders = []struct{ prefix, action string }{
	{"*** Add File: ", "write"},
	{"*** Update File: ", "write"},
	{"*** Move to: ", "write"},
	{"*** Delete File: ", "delete"},
}

// patchTargets lists the files an apply_patch command names in its headers.
// Hunk lines carry a leading "+", "-" or space and cannot match a header.
func patchTargets(patch string) []patchTarget {
	var out []patchTarget
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, h := range patchHeaders {
			if p, ok := strings.CutPrefix(line, h.prefix); ok && strings.TrimSpace(p) != "" {
				out = append(out, patchTarget{h.action, strings.TrimSpace(p)})
			}
		}
	}
	return out
}

// resolve anchors a relative patch path at the hook's working directory so
// the supervisor can place it in the project.
func resolve(cwd, path string) string {
	if filepath.IsAbs(path) || cwd == "" {
		return path
	}
	return filepath.Join(cwd, path)
}

func normalize(data []byte) ([]socket.Request, error) {
	var in Input
	if err := agenthook.Decode(data, &in); err != nil {
		return nil, err
	}
	return Normalize(in)
}

// Main runs the adapter against the process environment and standard streams.
func Main() int { return agenthook.Main(Spec.Agent, normalize) }
