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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/event"
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

	maxInput = 16 << 20
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
func Normalize(in Input, cwd string) (request socket.Request, skip bool, err error) {
	result := ""
	switch in.HookEventName {
	case "PreToolUse":
		request.Operation = "check"
	case "PostToolUse":
		request.Operation, result = "emit", "success"
	case "PostToolUseFailure":
		request.Operation, result = "emit", "failed"
	case "ConfigChange":
		if in.Source != "project_settings" && in.Source != "local_settings" {
			return request, true, nil
		}
		target := in.Source
		if rel, err := filepath.Rel(cwd, in.FilePath); in.FilePath != "" && err == nil && !strings.HasPrefix(rel, "..") {
			target = filepath.ToSlash(rel)
		}
		request.Operation = "check"
		request.Event = socket.Input{Type: "policy", Action: "tamper", Target: target, Producer: Producer, SessionID: identifier(in.SessionID)}
		return request, false, nil
	default:
		return request, true, nil
	}
	tool := identifier(in.ToolName)
	if tool == "" {
		return request, false, errors.New("hook input has no tool name")
	}
	var fields toolFields
	if len(in.ToolInput) > 0 {
		if err := json.Unmarshal(in.ToolInput, &fields); err != nil {
			return request, false, errors.New("tool_input is not a JSON object")
		}
	}
	e := socket.Input{Result: result, Producer: Producer, Tool: tool, AgentID: identifier(in.AgentID), AgentType: identifier(in.AgentType), CallID: identifier(in.ToolUseID), SessionID: identifier(in.SessionID)}
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
		u, err := url.Parse(fields.URL)
		if err != nil || u.Hostname() == "" {
			return request, false, errors.New("WebFetch tool input has no usable host")
		}
		// Only the host is policy-relevant. Userinfo, path, query and fragment
		// can carry credentials and are discarded here.
		e.Type, e.Action, e.Target = "network", "connect", strings.ToLower(u.Hostname())
	case "Bash":
		// SAGA is not a shell interpreter: the command text is never read. A
		// Bash call is recorded as a process execution; file and network effects
		// are left to the independent filesystem observer.
		e.Type, e.Action, e.Target = "process", "execute", tool
	default:
		e.Type, e.Action, e.Target = "tool", "call", tool
		if server, name, ok := strings.Cut(strings.TrimPrefix(in.ToolName, "mcp__"), "__"); strings.HasPrefix(in.ToolName, "mcp__") && ok && server != "" && name != "" {
			e.Target = identifier(server) + "/" + identifier(name)
		}
	}
	request.Event = e
	return request, false, nil
}

// identifier keeps printable ASCII without spaces, bounded to the lineage
// limit, so a tool or agent name can never smuggle a payload into the audit.
func identifier(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= 128 {
			break
		}
	}
	return b.String()
}

// Options wires the adapter to its environment. Send defaults to socket.Send.
type Options struct {
	Socket, RunID, Cwd string
	Send               func(string, socket.Request) (socket.Response, error)
}

// Run reads one hook event from stdin and answers Claude Code. It returns the
// process exit code: 0 leaves the tool call to Claude's normal permission flow,
// 2 blocks it. Every failure to obtain a policy decision returns 2.
func Run(stdin io.Reader, stdout, stderr io.Writer, opts Options) int {
	block := func(reason string) int {
		fmt.Fprintf(stderr, "SAGA preventive check unavailable; tool call blocked\nReason: %s\nStart the agent under supervision: saga-watchdog run -- claude\n", event.Redact(reason))
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxInput+1))
	if err != nil {
		return block("cannot read hook input")
	}
	if len(data) > maxInput {
		return block("hook input exceeds 16 MiB")
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		// The payload is never echoed: it may hold file contents or secrets.
		return block("hook input is not valid JSON")
	}
	request, skip, err := Normalize(in, opts.Cwd)
	if skip {
		return 0
	}
	if err != nil {
		return block(err.Error())
	}
	if opts.Socket == "" || opts.RunID == "" {
		return block("SAGA_WATCHDOG_SOCKET or SAGA_WATCHDOG_RUN_ID is not set")
	}
	request.RunID = opts.RunID
	send := opts.Send
	if send == nil {
		send = socket.Send
	}
	response, err := send(opts.Socket, request)
	if request.Operation == "emit" {
		if err != nil {
			fmt.Fprintf(stderr, "SAGA post-action report failed: %s\n", event.Redact(err.Error()))
			return 2
		}
		return 0
	}
	if err != nil {
		return block(err.Error())
	}
	d := response.Decision
	if d == nil || d.Action == "" {
		return block("watchdog response carries no decision")
	}
	if !response.Allowed {
		fmt.Fprintf(stderr, "SAGA blocked this tool call\nRule: %s\nTarget: %s\nReason: %s\n", d.RuleID, event.Redact(request.Event.Target), event.Redact(d.Reason))
		switch d.Action {
		case "pause":
			fmt.Fprintf(stderr, "Run %s is paused until an operator inspects it: saga-watchdog status; saga-watchdog resume %s\n", opts.RunID, opts.RunID)
		case "kill":
			fmt.Fprintf(stderr, "Run %s is being stopped by SAGA Watchdog\n", opts.RunID)
		}
		return 2
	}
	if d.Action != "allow" {
		// Allowed with a non-allow decision is a warning in enforce mode or a
		// recorded would-action in observe mode. Tell the operator, not Claude.
		message := fmt.Sprintf("SAGA Watchdog warning [%s]: %s", d.RuleID, d.Reason)
		if d.Action != "warn" {
			message = fmt.Sprintf("SAGA Watchdog observe mode: would %s [%s] %s (target %s)", d.Action, d.RuleID, d.Reason, request.Event.Target)
		}
		json.NewEncoder(stdout).Encode(map[string]string{"systemMessage": event.Redact(message)})
	}
	return 0
}

// Main runs the adapter against the process environment and standard streams.
func Main() int {
	cwd, _ := os.Getwd()
	return Run(os.Stdin, os.Stdout, os.Stderr, Options{Socket: os.Getenv("SAGA_WATCHDOG_SOCKET"), RunID: os.Getenv("SAGA_WATCHDOG_RUN_ID"), Cwd: cwd})
}
