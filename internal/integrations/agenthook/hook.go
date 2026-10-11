// Package agenthook is the shared half of every agent hook adapter. It reads
// one hook payload, hands it to an agent-specific normalizer, obtains the
// decision from the supervisor over the integration socket and answers the
// agent. It holds no safety rules: every decision comes from the policy
// engine, and every failure to obtain a decision blocks the tool call.
package agenthook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
)

// MaxInput bounds one hook payload.
const MaxInput = 16 << 20

// Normalizer maps one raw hook payload to the socket requests it implies. An
// empty result means the event is not evaluated. The error text must never
// contain tool arguments.
type Normalizer func(data []byte) ([]socket.Request, error)

// Options wires an adapter to its environment. Send defaults to socket.Send.
type Options struct {
	Socket, RunID string
	Send          func(string, socket.Request) (socket.Response, error)
}

// Run reads one hook event from stdin and answers the agent. It returns the
// process exit code: 0 leaves the tool call to the agent's normal permission
// flow, 2 blocks it. Every failure to obtain a policy decision returns 2.
// agent names the executable in the operator hint.
func Run(stdin io.Reader, stdout, stderr io.Writer, opts Options, agent string, normalize Normalizer) int {
	block := func(reason string) int {
		fmt.Fprintf(stderr, "SAGA preventive check unavailable; tool call blocked\nReason: %s\nStart the agent under supervision: saga-watchdog run -- %s\n", event.Redact(reason), agent)
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxInput+1))
	if err != nil {
		return block("cannot read hook input")
	}
	if len(data) > MaxInput {
		return block("hook input exceeds 16 MiB")
	}
	requests, err := normalize(data)
	if err != nil {
		return block(err.Error())
	}
	if len(requests) == 0 {
		return 0
	}
	if opts.Socket == "" || opts.RunID == "" {
		return block("SAGA_WATCHDOG_SOCKET or SAGA_WATCHDOG_RUN_ID is not set")
	}
	send := opts.Send
	if send == nil {
		send = socket.Send
	}
	var messages []string
	for _, request := range requests {
		request.RunID = opts.RunID
		response, err := send(opts.Socket, request)
		if request.Operation == "emit" {
			if err != nil {
				fmt.Fprintf(stderr, "SAGA post-action report failed: %s\n", event.Redact(err.Error()))
				return 2
			}
			continue
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
			// recorded would-action in observe mode. Tell the operator, not the agent.
			message := fmt.Sprintf("SAGA Watchdog warning [%s]: %s", d.RuleID, d.Reason)
			if d.Action != "warn" {
				message = fmt.Sprintf("SAGA Watchdog observe mode: would %s [%s] %s (target %s)", d.Action, d.RuleID, d.Reason, request.Event.Target)
			}
			messages = append(messages, event.Redact(message))
		}
	}
	if len(messages) > 0 {
		// Every supported agent shows systemMessage to the operator and treats
		// the call as allowed.
		json.NewEncoder(stdout).Encode(map[string]string{"systemMessage": strings.Join(messages, "\n")})
	}
	return 0
}

// Main runs an adapter against the process environment and standard streams.
func Main(agent string, normalize Normalizer) int {
	return Run(os.Stdin, os.Stdout, os.Stderr, Options{Socket: os.Getenv("SAGA_WATCHDOG_SOCKET"), RunID: os.Getenv("SAGA_WATCHDOG_RUN_ID")}, agent, normalize)
}

// Decode parses a hook payload into v. The payload is never echoed in the
// error: it may hold file contents or secrets.
func Decode(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return errors.New("hook input is not valid JSON")
	}
	return nil
}

// Identifier keeps printable ASCII without spaces, bounded to the lineage
// limit, so a tool or agent name can never smuggle a payload into the audit.
func Identifier(s string) string {
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

// Host returns the lowercase host of a URL. Only the host is policy-relevant:
// userinfo, path, query and fragment can carry credentials and are discarded.
func Host(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	return strings.ToLower(u.Hostname()), true
}

// MCPTarget turns a prefixed MCP tool name into the "server/tool" target,
// splitting server from tool at the first sep. ok is false for other names.
func MCPTarget(name, prefix, sep string) (string, bool) {
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	server, tool, ok := strings.Cut(strings.TrimPrefix(name, prefix), sep)
	if !ok || server == "" || tool == "" {
		return "", false
	}
	return Identifier(server) + "/" + Identifier(tool), true
}
