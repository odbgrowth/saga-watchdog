package main

import (
	"runtime/debug"
	"strings"
)

// version is set by release builds with -ldflags "-X main.version=X.Y.Z".
var version = "dev"

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		version = reportedVersion(version, info.Main.Version)
	}
}

// reportedVersion is the version a release build set, else the module version
// go install records (v0.5.1 for @v0.5.1, a pseudo-version for @main), else
// dev. A build from a local checkout records "(devel)".
func reportedVersion(set, module string) string {
	if set != "dev" || !strings.HasPrefix(module, "v") {
		return set
	}
	return strings.TrimPrefix(module, "v")
}
