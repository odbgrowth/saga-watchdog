#!/usr/bin/env bash
# Fail unless every required CI job finished with the result "success".
# The ci-gate job passes its `needs` context here, so a job that failed, was
# cancelled or skipped, or is missing from the context, never counts as green.
#
#   NEEDS_JSON='{"test":{"result":"success"}}' REQUIRED_JOBS="test" scripts/ci-gate.sh
#
#   NEEDS_JSON     JSON object of the needs context: {"<job id>": {"result": "..."}}
#   REQUIRED_JOBS  space-separated job ids that must all report "success"
set -euo pipefail

needs="${NEEDS_JSON:-}"
required="${REQUIRED_JOBS:-}"

if [[ -z "${needs//[[:space:]]/}" ]]; then
  echo "FAIL ci-gate: NEEDS_JSON is empty"
  exit 1
fi
if ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$needs"; then
  echo "FAIL ci-gate: NEEDS_JSON is not a JSON object"
  exit 1
fi

# Split on any whitespace, newlines included, and never expand globs.
set -f
# shellcheck disable=SC2206
jobs=($required)
set +f
if [[ "${#jobs[@]}" -eq 0 ]]; then
  echo "FAIL ci-gate: REQUIRED_JOBS is empty"
  exit 1
fi

fail=0
for job in "${jobs[@]}"; do
  result="$(jq -r --arg job "$job" '
    .[$job] as $need
    | if ($need | type) == "object" and ($need.result | type) == "string"
      then $need.result
      else "missing"
      end' <<<"$needs")"
  printf '%-20s %s\n' "$job" "$result"
  if [[ "$result" != "success" ]]; then
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "FAIL ci-gate: every required job must finish with success"
  exit 1
fi
echo "OK ci-gate: all required jobs succeeded"
