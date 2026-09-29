package policy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Normalize returns a slash-separated path relative to the canonical project
// root. Missing leaves are resolved through the nearest existing ancestor so a
// symlink followed by a not-yet-created file cannot hide an out-of-root target.
// This is an observation-time check, not an atomic OS filesystem sandbox.
func Normalize(root, target string) (string, error) {
	return normalize(root, target, true)
}

// normalize can retain the lexical name so resolving a symlink cannot erase
// protection attached to the path that was requested or observed.
func normalize(root, target string, followSymlinks bool) (string, error) {
	if target == "" || strings.ContainsRune(target, '\x00') {
		return "", errors.New("path is empty or contains a NUL byte")
	}
	portable := strings.ReplaceAll(target, "\\", "/")
	for _, segment := range strings.Split(portable, "/") {
		if segment == ".." {
			return "", errors.New("path traversal segments are not accepted")
		}
	}
	if runtime.GOOS != "windows" && (strings.HasPrefix(portable, "//") || (len(portable) > 1 && portable[1] == ':')) {
		return "", errors.New("foreign absolute path is not accepted")
	}
	canonicalRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	lexicalRoot := canonicalRoot
	canonicalRoot, err = filepath.EvalSymlinks(canonicalRoot)
	if err != nil {
		return "", fmt.Errorf("resolve project root symlinks: %w", err)
	}
	candidate := filepath.FromSlash(portable)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(canonicalRoot, candidate)
	}
	candidate = filepath.Clean(candidate)
	relative, err := contained(canonicalRoot, candidate)
	if err != nil {
		// macOS and project symlinks can give the root two legitimate names.
		var lexicalErr error
		relative, lexicalErr = contained(lexicalRoot, candidate)
		if lexicalErr != nil {
			return "", err
		}
	}
	if followSymlinks {
		resolved, err := resolveExisting(candidate)
		if err != nil {
			return "", err
		}
		relative, err = contained(canonicalRoot, resolved)
		if err != nil {
			return "", err
		}
	}
	relative = filepath.ToSlash(relative)
	if runtime.GOOS == "windows" {
		relative = strings.ToLower(relative)
	}
	return relative, nil
}

func contained(root, candidate string) (string, error) {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("path is outside the project root")
	}
	return relative, nil
}

func lexicalRootFile(root, target, name string) bool {
	root, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidate := filepath.FromSlash(strings.ReplaceAll(target, "\\", "/"))
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)
	roots := []string{root}
	if canonical, err := filepath.EvalSymlinks(root); err == nil {
		roots = append(roots, canonical)
	}
	for _, base := range roots {
		want := filepath.Join(base, name)
		if candidate == want || (runtime.GOOS == "windows" && strings.EqualFold(candidate, want)) {
			return true
		}
	}
	// Resolve only the parent: the policy leaf may itself have been replaced
	// by an external/dangling symlink. This also handles /var vs /private/var
	// combined with a separate alias of the project directory on macOS.
	parent, parentErr := filepath.EvalSymlinks(filepath.Dir(candidate))
	canonical, rootErr := filepath.EvalSymlinks(root)
	if parentErr == nil && rootErr == nil && parent == canonical && filepath.Base(candidate) == name {
		return true
	}
	return false
}

func resolveExisting(candidate string) (string, error) {
	var suffix []string
	current := candidate
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolve path symlinks: %w", err)
		}
		// A dangling symlink must not be mistaken for an ordinary missing leaf.
		if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("path contains a dangling symlink")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("path has no existing ancestor")
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

// Match supports ordinary per-segment globs plus ** for zero or more complete
// path segments. A trailing /** also matches the directory itself for pruning.
func Match(pattern, target string) bool {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	target = strings.ReplaceAll(target, "\\", "/")
	if runtime.GOOS == "windows" {
		pattern, target = strings.ToLower(pattern), strings.ToLower(target)
	}
	pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "./"), "/")
	target = strings.TrimSuffix(strings.TrimPrefix(target, "./"), "/")
	return matchSegments(strings.Split(pattern, "/"), strings.Split(target, "/"))
}

func matchSegments(pattern, target []string) bool {
	// Memoization keeps repeated ** patterns bounded by the number of segment
	// pairs instead of allowing exponential backtracking on an event path.
	memo := make(map[[2]int]bool)
	seen := make(map[[2]int]bool)
	var match func(int, int) bool
	match = func(p, t int) bool {
		key := [2]int{p, t}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		ok := false
		if p == len(pattern) {
			ok = t == len(target)
		} else if pattern[p] == "**" {
			ok = match(p+1, t) || (t < len(target) && match(p, t+1))
		} else if t < len(target) {
			matched, err := path.Match(pattern[p], target[t])
			ok = err == nil && matched && match(p+1, t+1)
		}
		memo[key] = ok
		return ok
	}
	return match(0, 0)
}

// Controls cannot be hidden by a broad ignore such as .git/** or **.
var controlPatterns = []string{".saga-watchdog.yaml", ".git/config", ".git/hooks/**", ".github/workflows/**"}

func Ignored(target string, patterns []string) bool {
	target = strings.TrimSuffix(strings.ReplaceAll(target, "\\", "/"), "/")
	if runtime.GOOS == "windows" {
		target = strings.ToLower(target)
	}
	for _, control := range controlPatterns {
		if Match(control, target) || strings.HasPrefix(control, target+"/") || target == "." {
			return false
		}
	}
	for _, pattern := range patterns {
		if Match(pattern, target) {
			return true
		}
	}
	return false
}
