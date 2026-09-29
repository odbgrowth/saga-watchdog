package gitinfo

import "testing"

func TestProtectedBranchGlobs(t *testing.T) {
	for _, branch := range []string{"release/a", "release/team/task", "main"} {
		if !Protected(branch, []string{"main", "release/**"}) {
			t.Fatalf("branch %q not protected", branch)
		}
	}
	if Protected("codex/new", []string{"main", "release/**"}) {
		t.Fatal("working branch protected unexpectedly")
	}
}
