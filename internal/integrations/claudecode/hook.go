// Package claudecode adapts Claude Code hook events to canonical SAGA events.
// It holds no safety rules: every decision comes from the supervisor's policy
// engine through the existing integration socket, and every failure to obtain
// a decision blocks the tool call.
package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
)

const (
	// Producer identifies this adapter in audit metadata.
	Producer = "claude-code"
	// Command is the shell-form hook command written into Claude settings.
	Command = "saga-watchdog claude hook"
	// Matcher lists the tools SAGA evaluates. Read-only tools and WebSearch are
	// deliberately absent: SAGA has no file-read monitoring and a search query
	// is not a host. Unmatched tools never reach the adapter.
	Matcher = "Write|Edit|MultiEdit|NotebookEdit|Bash|WebFetch|mcp__.*"
	// ConfigMatcher selects the settings scopes whose change can disable the hook.
	ConfigMatcher = "project_settings|local_settings"
	// MinimumVersion is the first Claude Code release with onFailure: "block".
	MinimumVersion = "2.1.295"
)

// Input holds the documented hook fields SAGA reads. Unknown fields are ignored
// for forward compatibility. tool_input is decoded per tool for one path or URL
// field and otherwise discarded; it is never logged or forwarded.
type Input struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolUseID     string          `json:"tool_use_id"`
	AgentID       string          `json:"agent_id"`
	AgentType     string          `json:"agent_type"`
	Source        string          `json:"source"`
	FilePath      string          `json:"file_path"`
}

type toolFields struct {
	FilePath     string `json:"file_path"`
	NotebookPath string `json:"notebook_path"`
	URL          string `json:"url"`
}

// Normalize maps one hook event to a socket request. skip reports an event
// SAGA does not evaluate; err reports input that cannot be interpreted safely.
// The error text never contains tool arguments.
func Normalize(in Input) (request socket.Request, skip bool, err error) {
	result := ""
	switch in.HookEventName {
	case "PreToolUse":
		request.Operation = "check"
	case "PostToolUse":
		request.Operation, result = "emit", "success"
	case "PostToolUseFailure":
		request.Operation, result = "emit", "failed"
	case "ConfigChange":
		// A project or local settings change is reported as a write to the
		// file Claude names. The policy engine decides: kill when that file
		// carries the SAGA hook, pause for the sibling settings file while the
		// hook is active. Without an authoritative path the change cannot be
		// placed in the project, so it is refused rather than guessed from the
		// hook's working directory.
		if in.Source != "project_settings" && in.Source != "local_settings" {
			return request, true, nil
		}
		if in.FilePath == "" {
			return request, false, errors.New("ConfigChange carries no file_path")
		}
		request.Operation = "check"
		request.Event = socket.Input{Type: "file", Action: "write", Target: in.FilePath, Producer: Producer, SessionID: agenthook.Identifier(in.SessionID)}
		return request, false, nil
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
	e := socket.Input{Result: result, Producer: Producer, Tool: tool, AgentID: agenthook.Identifier(in.AgentID), AgentType: agenthook.Identifier(in.AgentType), CallID: agenthook.Identifier(in.ToolUseID), SessionID: agenthook.Identifier(in.SessionID)}
	switch in.ToolName {
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		path := fields.FilePath
		if in.ToolName == "NotebookEdit" {
			path = fields.NotebookPath
		}
		if path == "" {
			return request, false, fmt.Errorf("%s tool input has no path", in.ToolName)
		}
		e.Type, e.Action, e.Target = "file", "write", path
	case "WebFetch":
		host, ok := agenthook.Host(fields.URL)
		if !ok {
			return request, false, errors.New("WebFetch tool input has no usable host")
		}
		e.Type, e.Action, e.Target = "network", "connect", host
	case "Bash":
		// SAGA is not a shell interpreter: the command text is never read. A
		// Bash call is recorded as a process execution; file and network effects
		// are left to the independent filesystem observer.
		e.Type, e.Action, e.Target = "process", "execute", tool
	default:
		e.Type, e.Action, e.Target = "tool", "call", tool
		if target, ok := agenthook.MCPTarget(in.ToolName, "mcp__", "__"); ok {
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

// Options wires the adapter to its environment.
type Options = agenthook.Options

// Run reads one hook event from stdin and answers Claude Code; see agenthook.Run.
func Run(stdin io.Reader, stdout, stderr io.Writer, opts Options) int {
	return agenthook.Run(stdin, stdout, stderr, opts, Spec.Agent, normalize)
}

// Main runs the adapter against the process environment and standard streams.
func Main() int { return agenthook.Main(Spec.Agent, normalize) }
