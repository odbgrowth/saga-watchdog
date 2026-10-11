#!/usr/bin/env bash
# Verify that the documented release version is consistent, and, when a tag
# is given, that it is the version being released.
#
#   scripts/check-release-refs.sh           # CI: README and SECURITY.md agree
#   scripts/check-release-refs.sh v0.2.0    # release: both name this tag
set -euo pipefail
cd "$(dirname "$0")/.."

status="$(sed -n 's/^\*\*Status:\*\* \(v[0-9]*\.[0-9]*\.[0-9]*\) is the current release.*/\1/p' README.md)"
install="$(sed -n 's|^go install github.com/odbgrowth/saga-watchdog/cmd/saga-watchdog@\(v[0-9]*\.[0-9]*\.[0-9]*\)$|\1|p' README.md)"
security="$(sed -n 's/^\(v[0-9]*\.[0-9]*\.[0-9]*\) is the current release\..*/\1/p' SECURITY.md)"

fail=0
check() {
  if [[ "$2" != "$3" ]]; then
    echo "FAIL $1: found '$2', want '$3'"
    fail=1
  fi
}
want="${1:-$status}"
[[ -n "$want" ]] || { echo "FAIL README.md: no '**Status:** vX.Y.Z is the current release' line"; exit 1; }
check "README.md status line" "$status" "$want"
check "README.md go install line" "$install" "$want"
check "SECURITY.md supported versions" "$security" "$want"
if [[ "$fail" -ne 0 ]]; then
  echo "Update the release references before tagging; see CONTRIBUTING.md, Release process."
  exit 1
fi
echo "OK release references name $want"
