package main

import "testing"

// go install sets no -ldflags, so the version comes from the module version
// it records; a release build's own version always wins.
func TestReportedVersion(t *testing.T) {
	for _, tc := range []struct{ set, module, want string }{
		{"0.5.1", "v0.5.1", "0.5.1"},
		{"0.5.1", "(devel)", "0.5.1"},
		{"dev", "v0.5.1", "0.5.1"},
		{"dev", "v0.5.2-0.20261014110000-abcdef123456", "0.5.2-0.20261014110000-abcdef123456"},
		{"dev", "(devel)", "dev"},
		{"dev", "", "dev"},
	} {
		if got := reportedVersion(tc.set, tc.module); got != tc.want {
			t.Errorf("reportedVersion(%q, %q) = %q, want %q", tc.set, tc.module, got, tc.want)
		}
	}
}
