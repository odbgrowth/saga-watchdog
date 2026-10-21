// Package config loads a small, strictly validated per-project policy.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const Filename = ".saga-watchdog.yaml"
const DefaultYAML = "version: 1\nprofile: coding-agent\nmode: enforce\n"

type Config struct {
	Version    int        `yaml:"version"`
	Profile    string     `yaml:"profile"`
	Mode       string     `yaml:"mode"`
	Project    Project    `yaml:"project"`
	Run        Run        `yaml:"run"`
	Git        Git        `yaml:"git"`
	Filesystem Filesystem `yaml:"filesystem"`
	Escalation Escalation `yaml:"escalation"`
	Network    Network    `yaml:"network"`
	Tools      Tools      `yaml:"tools"`
	// SecurityContext, Effects and Replication are optional. Without them a
	// run behaves exactly as before: no persistent state, no replication rules
	// beyond the defaults below.
	SecurityContext SecurityContext     `yaml:"security_context"`
	Effects         map[string][]string `yaml:"effects"`
	Replication     Replication         `yaml:"replication"`
}

// SecurityContext names the authority envelope a project runs in. Together
// with the operator (from the invoking environment) and the project (derived
// by Watchdog) it keys persistent security state. The name is not security by
// itself: it only selects which unresolved restrictions apply. Changing it is
// a deliberate operator decision that starts a fresh context.
type SecurityContext struct {
	AuthorizationContext string        `yaml:"authorization_context"`
	Retention            time.Duration `yaml:"retention"`
	SeriousRetention     time.Duration `yaml:"serious_retention"`
}

// Replication authorizes new agent instances and runtimes. Everything not
// listed is unauthorized: authority does not replicate by default.
type Replication struct {
	SameHostWorkers    int      `yaml:"same_host_workers"`
	AllowAgents        []string `yaml:"allow_agents"`
	InferenceEndpoints []string `yaml:"inference_endpoints"`
	RemoteHosts        []string `yaml:"remote_hosts"`
}

// EffectTypes are the event types an effect pattern may name.
var EffectTypes = []string{"network", "tool", "file", "git", "agent", "runtime", "inference", "remote"}

var (
	contextName = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	effectName  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	identifier  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,252}$`)
	// OperatorID is the trusted operator identity format, such as human:onno.
	OperatorID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}:[A-Za-z0-9._@+-]{1,128}$`)
)

type Project struct {
	Name string `yaml:"name"`
}
type Run struct {
	MaxDuration     time.Duration `yaml:"max_duration"`
	StopGracePeriod time.Duration `yaml:"stop_grace_period"`
	// Unattended keeps a paused run's process group running: no operator is
	// present to resume, so enforcement continues through denied pre-action
	// checks while the agent is left to finish or exit on its own.
	Unattended bool `yaml:"unattended"`
	// RequirePreventiveHook refuses to start a run unless the agent being
	// launched is a supported one whose own preventive hook is configured in
	// this project and passes the locally checkable prerequisites. A generic
	// command cannot be verified and is refused. Off by default: a run without
	// a hook keeps supervision and post-action observation, as before.
	RequirePreventiveHook bool `yaml:"require_preventive_hook"`
}
type Git struct {
	ProtectedBranches []string `yaml:"protected_branches"`
	AllowProtected    bool     `yaml:"allow_protected"`
}
type Filesystem struct {
	Protect         []string      `yaml:"protect"`
	Ignore          []string      `yaml:"ignore"`
	DeleteThreshold int           `yaml:"delete_threshold"`
	DeleteWindow    time.Duration `yaml:"delete_window"`
}
type Escalation struct {
	Window     time.Duration `yaml:"window"`
	WarnAfter  int           `yaml:"warn_after"`
	PauseAfter int           `yaml:"pause_after"`
	KillAfter  int           `yaml:"kill_after"`
	// ShellFollowUp counts a shell command that follows a denial as an
	// alternative route, once per denial. A denied fetch or tool call followed
	// by curl in a shell is the pattern this catches.
	ShellFollowUp bool `yaml:"shell_follow_up"`
}

// Network governs cooperative network checks by hostname. In denylist mode
// (the default) every host is allowed unless denied. In allowlist mode a host
// must be listed in Allow, or granted for the run by an operator, or the check
// pauses the run. Deny always wins. An Allow entry starting with "." matches
// that domain and every subdomain.
type Network struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	// DenyRedirectors pauses connections to well-known URL shorteners and
	// redirectors unless the host is explicitly allowed or granted. Agents have
	// used them to get around fetch restrictions; the list is a tripwire, not
	// a complete catalogue.
	DenyRedirectors bool `yaml:"deny_redirectors"`
}

// Tools governs cooperative tool calls by their canonical identifier, such as
// an MCP tool "server/tool" or a tool name, with path-style globs. Modes work
// as for Network.
type Tools struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Default returns fresh slices so one project's overrides cannot change another.
func Default() Config {
	return Config{
		Version: 1, Profile: "coding-agent", Mode: "enforce",
		Run: Run{MaxDuration: 2 * time.Hour, StopGracePeriod: 5 * time.Second},
		Git: Git{ProtectedBranches: []string{"main", "master"}},
		Filesystem: Filesystem{
			Protect:         []string{Filename, ".git/config", ".git/hooks/**", ".github/workflows/**", "**/.env", "**/.env.*", "**/credentials*", "**/secrets*", "**/*.pem", "**/*.key"},
			Ignore:          []string{"**/node_modules/**", "**/vendor/**", ".git/objects/**", "**/dist/**", "**/build/**"},
			DeleteThreshold: 100, DeleteWindow: 10 * time.Second,
		},
		Escalation:      Escalation{Window: 120 * time.Second, WarnAfter: 2, PauseAfter: 3, KillAfter: 5, ShellFollowUp: true},
		Network:         Network{Mode: "denylist", DenyRedirectors: true},
		Tools:           Tools{Mode: "denylist"},
		SecurityContext: SecurityContext{Retention: 24 * time.Hour, SeriousRetention: 7 * 24 * time.Hour},
	}
}

func Load(filename string) (Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return Config{}, fmt.Errorf("open policy %s: %w", filename, err)
	}
	defer f.Close()
	return Parse(io.LimitReader(f, 64*1024+1))
}

// Parse accepts exactly one mapping document, with no unknown fields, duplicate
// keys, aliases, or null values. Bounded input prevents accidental huge policies.
func Parse(r io.Reader) (Config, error) {
	cfg := Default()
	if err := DecodeStrict(r, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// DecodeStrict shares the bounded YAML syntax rules across the separate CLI and
// service configurations. Each caller validates its own schema and defaults.
func DecodeStrict(r io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if len(data) > 64*1024 {
		return errors.New("policy exceeds 64 KiB")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse policy YAML: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("policy must be a non-empty YAML mapping")
	}
	if err := validateNode(&doc); err != nil {
		return err
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse policy YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("policy must contain exactly one YAML document")
	}
	return nil
}

func validateNode(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Tag == "!!null" {
		return fmt.Errorf("policy line %d: aliases and null values are not supported", n.Line)
	}
	for _, child := range n.Content {
		if err := validateNode(child); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("version must be 1")
	}
	if c.Profile != "coding-agent" {
		return errors.New("profile must be coding-agent")
	}
	if c.Mode != "observe" && c.Mode != "enforce" {
		return errors.New("mode must be observe or enforce")
	}
	if len(c.Project.Name) > 128 || strings.ContainsFunc(c.Project.Name, unicode.IsControl) {
		return errors.New("project.name must be at most 128 bytes without control characters")
	}
	if c.Run.MaxDuration <= 0 || c.Run.MaxDuration > 7*24*time.Hour {
		return errors.New("run.max_duration must be greater than 0 and at most 168h")
	}
	if c.Run.StopGracePeriod <= 0 || c.Run.StopGracePeriod > time.Minute {
		return errors.New("run.stop_grace_period must be greater than 0 and at most 1m")
	}
	if c.Filesystem.DeleteWindow <= 0 || c.Filesystem.DeleteWindow > time.Hour {
		return errors.New("filesystem.delete_window must be greater than 0 and at most 1h")
	}
	if c.Filesystem.DeleteThreshold < 1 || c.Filesystem.DeleteThreshold > 100000 {
		return errors.New("filesystem.delete_threshold must be between 1 and 100000")
	}
	if c.Escalation.Window <= 0 || c.Escalation.Window > time.Hour {
		return errors.New("escalation.window must be greater than 0 and at most 1h")
	}
	if c.Escalation.WarnAfter < 2 || c.Escalation.PauseAfter <= c.Escalation.WarnAfter || c.Escalation.KillAfter <= c.Escalation.PauseAfter || c.Escalation.KillAfter > 100000 {
		return errors.New("escalation thresholds must satisfy 2 <= warn_after < pause_after < kill_after <= 100000")
	}
	for field, patterns := range map[string][]string{"filesystem.protect": c.Filesystem.Protect, "filesystem.ignore": c.Filesystem.Ignore} {
		if len(patterns) > 256 {
			return fmt.Errorf("%s supports at most 256 patterns", field)
		}
		for _, pattern := range patterns {
			if err := validPattern(pattern); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	for _, branch := range c.Git.ProtectedBranches {
		if len(branch) > 256 {
			return errors.New("git.protected_branches patterns must be at most 256 bytes")
		}
		if err := validPattern(branch); err != nil {
			return fmt.Errorf("git.protected_branches: %w", err)
		}
	}
	if c.Tools.Mode != "denylist" && c.Tools.Mode != "allowlist" {
		return errors.New("tools.mode must be denylist or allowlist")
	}
	for field, patterns := range map[string][]string{"tools.deny": c.Tools.Deny, "tools.allow": c.Tools.Allow} {
		if len(patterns) > 256 {
			return fmt.Errorf("%s supports at most 256 patterns", field)
		}
		for _, pattern := range patterns {
			if err := validPattern(pattern); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	if c.Network.Mode != "denylist" && c.Network.Mode != "allowlist" {
		return errors.New("network.mode must be denylist or allowlist")
	}
	for field, hosts := range map[string][]string{"network.deny": c.Network.Deny, "network.allow": c.Network.Allow} {
		if len(hosts) > 256 {
			return fmt.Errorf("%s supports at most 256 hostnames", field)
		}
		for _, host := range hosts {
			// Only the allow list accepts a leading dot: ".example.com" covers the
			// domain and its subdomains. Denials stay exact.
			if field == "network.allow" {
				host = strings.TrimPrefix(host, ".")
			}
			if err := validHost(host); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	sc := c.SecurityContext
	if sc.AuthorizationContext != "" && !contextName.MatchString(sc.AuthorizationContext) {
		return errors.New("security_context.authorization_context must be 1-64 lowercase letters, digits or ._:-")
	}
	if sc.Retention < time.Minute || sc.Retention > 90*24*time.Hour || sc.SeriousRetention < sc.Retention || sc.SeriousRetention > 90*24*time.Hour {
		return errors.New("security_context retention must satisfy 1m <= retention <= serious_retention <= 2160h")
	}
	if len(c.Effects) > 64 {
		return errors.New("effects supports at most 64 named effects")
	}
	for name, patterns := range c.Effects {
		if !effectName.MatchString(name) {
			return fmt.Errorf("effect name %q must be 1-64 lowercase letters, digits or ._-", name)
		}
		if len(patterns) == 0 || len(patterns) > 64 {
			return fmt.Errorf("effect %s needs between 1 and 64 type:pattern entries", name)
		}
		for _, entry := range patterns {
			typ, pattern, ok := strings.Cut(entry, ":")
			if !ok || !slices.Contains(EffectTypes, typ) {
				return fmt.Errorf("effect %s: %q must be type:pattern with type one of %s", name, entry, strings.Join(EffectTypes, ", "))
			}
			var err error
			if typ == "network" {
				err = validHost(strings.TrimPrefix(pattern, "."))
			} else {
				err = validPattern(pattern)
			}
			if err != nil {
				return fmt.Errorf("effect %s: %w", name, err)
			}
		}
	}
	r := c.Replication
	if r.SameHostWorkers < 0 || r.SameHostWorkers > 64 {
		return errors.New("replication.same_host_workers must be between 0 and 64")
	}
	for field, list := range map[string][]string{"replication.allow_agents": r.AllowAgents, "replication.inference_endpoints": r.InferenceEndpoints, "replication.remote_hosts": r.RemoteHosts} {
		if len(list) > 64 {
			return fmt.Errorf("%s supports at most 64 entries", field)
		}
		for _, entry := range list {
			var err error
			if field == "replication.allow_agents" {
				err = validPattern(entry)
			} else if !identifier.MatchString(entry) {
				err = fmt.Errorf("invalid identifier %q", entry)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	return nil
}

func validHost(host string) error {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\*?@:#\r\n\t") {
		return errors.New("hostnames must be exact, without ports, URL schemes or wildcards")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("invalid hostname label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' {
				return errors.New("hostnames must use ASCII letters, digits and hyphens (use punycode for international names)")
			}
		}
	}
	return nil
}

func validPattern(pattern string) error {
	if pattern == "" || len(pattern) > 1024 || strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "\\:\x00\r\n") {
		return fmt.Errorf("invalid project-relative glob %q", pattern)
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return fmt.Errorf("glob %q contains an empty or traversal segment", pattern)
		}
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "test"); err != nil {
			return fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
	}
	return nil
}
