// Package authority keeps security state that must outlive a single run: the
// trusted security context a run belongs to, the restrictions earlier runs in
// that context earned, and the provenance of agent instances.
//
// Invariants:
//   - Failure never expands authority.
//   - Authority-expansion history survives model sessions, processes and runs.
//   - Security identity is operator + project + authorization context, never
//     a model session, process or self-reported field.
//   - Authority does not replicate: a child instance starts with no grants.
//     Restrictions propagate through the shared context; permissions do not.
//   - Model output is never authority: no event can clear, reset or approve
//     security state. Only an operator, a trusted grant, expiry or a new
//     trusted authorization context ends a restriction, and each is audited.
package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
)

// OperatorEnv names the environment variable that carries the operator
// identity at invocation. The supervisor removes it from the agent's
// environment.
const OperatorEnv = "SAGA_WATCHDOG_OPERATOR"

// Context is the trusted scope of persistent security state. Every field comes
// from Watchdog or trusted operator configuration; none from an event.
type Context struct {
	OperatorID             string `json:"operator_id"`
	ProjectID              string `json:"project_id"`
	Project                string `json:"project"`
	AuthorizationContextID string `json:"authorization_context_id"`
}

// Complete reports whether every identifying field is present.
func (c Context) Complete() bool {
	return c.OperatorID != "" && c.ProjectID != "" && c.AuthorizationContextID != ""
}

// ID is a stable, opaque identifier of the context.
func (c Context) ID() string {
	h := sha256.Sum256([]byte(c.OperatorID + "\x00" + c.ProjectID + "\x00" + c.AuthorizationContextID))
	return "ctx_" + hex.EncodeToString(h[:12])
}

// Resolve builds the context from trusted sources and explains why persistent
// correlation is unavailable when it is. Identity is never guessed.
func Resolve(operator, authorizationContext, projectID, project string) (Context, string) {
	c := Context{OperatorID: operator, ProjectID: projectID, Project: project, AuthorizationContextID: authorizationContext}
	switch {
	case operator == "":
		return c, "operator identity unavailable: set " + OperatorEnv + "=human:<name> when invoking saga-watchdog"
	case !config.OperatorID.MatchString(operator):
		c.OperatorID = ""
		return c, OperatorEnv + " must look like human:<name> (kind:identifier)"
	case projectID == "":
		return c, "project identity unavailable"
	case authorizationContext == "":
		return c, "no security_context.authorization_context in the policy"
	}
	return c, ""
}

// Instance records the provenance of one agent instance. Provenance is
// "trusted" only for instances Watchdog started itself within a complete
// trusted context; everything else is "unknown", and unknown never implies
// trust or authority.
type Instance struct {
	ID                     string `json:"instance_id"`
	ParentID               string `json:"parent_instance_id,omitempty"`
	PrincipalID            string `json:"principal_id"`
	OperatorID             string `json:"operator_id,omitempty"`
	ProjectID              string `json:"project_id,omitempty"`
	AuthorizationContextID string `json:"authorization_context_id,omitempty"`
	ContextID              string `json:"context_id,omitempty"`
	HostID                 string `json:"host_id"`
	RunID                  string `json:"run_id,omitempty"`
	ArtifactID             string `json:"artifact_id,omitempty"`
	RuntimeType            string `json:"runtime_type"`
	AuthorizedByRule       string `json:"authorized_by_rule,omitempty"`
	Provenance             string `json:"provenance"`
}

// NewInstanceID returns a fresh instance identifier.
func NewInstanceID() string { return event.NewID("agtinst") }

// Host identifies the machine Watchdog runs on and the names that refer to it.
type Host struct {
	ID    string
	names map[string]bool
}

// LocalHost derives a stable local host identifier from the hostname. It is a
// label for the audit trail, not an attested machine identity.
func LocalHost() Host {
	name, _ := os.Hostname()
	name = strings.ToLower(name)
	h := sha256.Sum256([]byte(name))
	id := "host_" + hex.EncodeToString(h[:6])
	names := map[string]bool{"": true, "localhost": true, "127.0.0.1": true, "::1": true, id: true}
	if name != "" {
		names[name] = true
	}
	return Host{ID: id, names: names}
}

// Classify maps a reported host to the identifier recorded for it and whether
// it is another machine. An absent host means this machine.
func (h Host) Classify(reported string) (id string, remote bool) {
	reported = strings.ToLower(strings.TrimSuffix(reported, "."))
	if h.names[reported] {
		return h.ID, false
	}
	return reported, true
}

// ArtifactID fingerprints the executable an instance runs as sha256:<hex>, or
// returns "" when it cannot be read. Large binaries are hashed up to 512 MiB.
func ArtifactID(command string) string {
	path, err := exec.LookPath(command)
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 512<<20)); err != nil {
		return ""
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ErrCorrupt reports persistent state that cannot be read safely. A run refuses
// to start rather than silently dropping restrictions.
var ErrCorrupt = errors.New("persistent authority state is unreadable")
