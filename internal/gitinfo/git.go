// Package gitinfo contains the few Git queries needed by the supervisor.
package gitinfo

import (
	"context"
	"fmt"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Info struct {
	Root, Branch, GitDir, CommonDir string
	Dirty                           bool
	Remotes                         []string
}

func query(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w", args[0], err)
	}
	return strings.TrimSpace(string(b)), nil
}

func Inspect(dir string) (Info, error) {
	var i Info
	var err error
	if i.Root, err = query(dir, "rev-parse", "--show-toplevel"); err != nil {
		return i, fmt.Errorf("run inside a Git working tree: %w", err)
	}
	if i.Root, err = filepath.EvalSymlinks(i.Root); err != nil {
		return i, err
	}
	if i.Branch, err = Branch(i.Root); err != nil {
		return i, err
	}
	if i.GitDir, err = query(i.Root, "rev-parse", "--absolute-git-dir"); err != nil {
		return i, err
	}
	if i.CommonDir, err = query(i.Root, "rev-parse", "--path-format=absolute", "--git-common-dir"); err != nil {
		return i, err
	}
	s, err := query(i.Root, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return i, err
	}
	i.Dirty = s != ""
	// Names only: remote URLs can contain embedded credentials.
	s, err = query(i.Root, "remote")
	if err != nil {
		return i, err
	}
	i.Remotes = strings.Fields(s)
	return i, nil
}

func Branch(root string) (string, error) {
	branch, err := query(root, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil {
		return branch, nil
	}
	if _, err = query(root, "rev-parse", "--verify", "HEAD"); err != nil {
		return "", err
	}
	return "HEAD", nil
}

func Protected(branch string, patterns []string) bool {
	for _, p := range patterns {
		if policy.Match(p, branch) {
			return true
		}
	}
	return false
}
