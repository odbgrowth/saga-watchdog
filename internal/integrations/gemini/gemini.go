// Package gemini adapts Gemini CLI hook events to canonical SAGA events.
// Gemini CLI sends BeforeTool and AfterTool payloads on stdin; exit code 2
// blocks with stderr as the reason, and exit 0 with a JSON systemMessage shows
// a note to the operator. Verified against Gemini CLI 0.63.0 docs/hooks and
// packages/core/src/hooks.
package gemini

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
)

const (
	// Producer identifies this adapter in audit metadata.
	Producer = "gemini-cli"
	// Command is the shell-form hook command written into .gemini/settings.json.
	Command = "saga-watchdog gemini hook"
	// Matcher is a regular expression that Gemini CLI tests against the tool
	// name without anchors, so it carries its own. Read-only tools are absent;
	// mcp_ covers every MCP tool.
	Matcher = "^(write_file|replace|run_shell_command|web_fetch|google_web_search|invoke_agent|mcp_.*)$"
	// HookName is the name hooksConfig.disabled can use to switch the hook off.
	HookName = "saga-watchdog"
)

// Files are the project-scoped Gemini CLI settings that carry or disable the
// SAGA hook. User and system settings are outside the project.
var Files = []string{".gemini/settings.json"}

// Spec is the Gemini CLI hook configuration.
var Spec = agenthook.Spec{
	Name: "Gemini CLI", Agent: "gemini", Producer: Producer, Command: Command, Matcher: Matcher, PreEvent: "BeforeTool", Files: Files,
	Hooks:    hooks,
	Disabled: disabled,
}

// hooks returns the hook groups SAGA installs. Gemini CLI has no fail-closed
// option: an adapter that cannot start or times out is logged and the call
// proceeds, so the adapter must exist on PATH; saga-watchdog gemini doctor
// checks that. The timeout is in milliseconds.
func hooks() map[string]any {
	group := func() []any {
		return []any{map[string]any{"matcher": Matcher, "hooks": []any{map[string]any{"name": HookName, "type": "command", "command": Command, "timeout": 10000}}}}
	}
	return map[string]any{"BeforeTool": group(), "AfterTool": group()}
}

// disabled reports a settings file that switches hooks off globally or the
// SAGA hook off by name.
func disabled(obj map[string]any) bool {
	cfg, _ := obj["hooksConfig"].(map[string]any)
	if cfg["enabled"] == false {
		return true
	}
	list, _ := cfg["disabled"].([]any)
	for _, name := range list {
		if name == HookName {
			return true
		}
	}
	return false
}

// Input holds the documented hook fields SAGA reads. tool_input is decoded
// per tool for one path or URL field and otherwise discarded.
type Input struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
}

type toolFields struct {
	FilePath string `json:"file_path"`
	URL      string `json:"url"`
}

type toolResponse struct {
	Error json.RawMessage `json:"error"`
}

// Normalize maps one hook event to a socket request. skip reports an event
// SAGA does not evaluate; err reports input that cannot be interpreted safely.
// The error text never contains tool arguments.
func Normalize(in Input) (request socket.Request, skip bool, err error) {
	result := ""
	switch in.HookEventName {
	case "BeforeTool":
		request.Operation = "check"
	case "AfterTool":
		request.Operation, result = "emit", "success"
		var r toolResponse
		if len(in.ToolResponse) > 0 {
			if err := json.Unmarshal(in.ToolResponse, &r); err != nil {
				return request, false, errors.New("tool_response is not a JSON object")
			}
		}
		if len(r.Error) > 0 && string(r.Error) != "null" {
			result = "failed"
		}
	default:
		return request, true, nil
	}
	tool := agenthook.Identifier(in.ToolName)
	if tool == "" {
		return request, false, errors.New("hook input has no tool name")
	}
	var fields toolFields
	if len(in.ToolInput) > 0 {
		if err := json.Unmarshal(in.ToolInput, &fields); err != nil {
			return request, false, errors.New("tool_input is not a JSON object")
		}
	}
	e := socket.Input{Result: result, Producer: Producer, Tool: tool, SessionID: agenthook.Identifier(in.SessionID)}
	switch in.ToolName {
	case "write_file", "replace":
		if fields.FilePath == "" {
			return request, false, fmt.Errorf("%s tool input has no path", in.ToolName)
		}
		e.Type, e.Action, e.Target = "file", "write", fields.FilePath
	case "run_shell_command":
		// SAGA is not a shell interpreter: the command text is never read.
		e.Type, e.Action, e.Target = "process", "execute", tool
	case "web_fetch":
		// web_fetch takes a URL or a prompt with URLs written in prose. The
		// prompt is never read; a prompt-only fetch is recorded as a tool call.
		switch host, ok := agenthook.Host(fields.URL); {
		case ok:
			e.Type, e.Action, e.Target = "network", "connect", host
		case fields.URL != "":
			return request, false, errors.New("web_fetch tool input has no usable host")
		default:
			e.Type, e.Action, e.Target = "tool", "call", tool
		}
	default:
		e.Type, e.Action, e.Target = "tool", "call", tool
		if target, ok := agenthook.MCPTarget(in.ToolName, "mcp_", "_"); ok {
			e.Target = target
		}
	}
	request.Event = e
	return request, false, nil
}

func normalize(data []byte) ([]socket.Request, error) {
	var in Input
	if err := agenthook.Decode(data, &in); err != nil {
		return nil, err
	}
	request, skip, err := Normalize(in)
	if err != nil || skip {
		return nil, err
	}
	return []socket.Request{request}, nil
}

// Main runs the adapter against the process environment and standard streams.
func Main() int { return agenthook.Main(Spec.Agent, normalize) }
