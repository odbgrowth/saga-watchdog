#!/usr/bin/env bash
# Self-test for the CI gate. It checks scripts/ci-gate.sh against every result
# a needed job can report, checks that scripts/ci-summary.sh never fails, and
# checks that .github/workflows/ci.yml keeps the gate wired up: the required
# jobs, the needs of ci-gate and `if: always()`. Needs bash, jq and awk only.
#
#   scripts/ci-gate_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

workflow=.github/workflows/ci.yml
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

checks=0
failures=0
ok() {
  checks=$((checks + 1))
  echo "ok   $1"
}
bad() {
  checks=$((checks + 1))
  failures=$((failures + 1))
  echo "FAIL $1"
}

# gate WANT LABEL NEEDS_JSON REQUIRED_JOBS: ci-gate.sh must exit with WANT.
gate() {
  local want="$1" label="$2" rc=0
  NEEDS_JSON="$3" REQUIRED_JOBS="$4" scripts/ci-gate.sh >/dev/null 2>&1 || rc=$?
  if [[ "$rc" -eq "$want" ]]; then ok "gate: $label"; else bad "gate: $label (exit $rc, want $want)"; fi
}

all_ok='{"test":{"result":"success"},"race":{"result":"success"},"docker-acceptance":{"result":"success"}}'
req="test race docker-acceptance"

gate 0 "all required jobs succeeded" "$all_ok" "$req"
gate 0 "extra job that is not required is ignored" \
  '{"test":{"result":"success"},"race":{"result":"success"},"other":{"result":"failure"}}' "test race"
gate 1 "one job failed" \
  '{"test":{"result":"success"},"race":{"result":"failure"},"docker-acceptance":{"result":"success"}}' "$req"
gate 1 "one job cancelled" \
  '{"test":{"result":"success"},"race":{"result":"cancelled"},"docker-acceptance":{"result":"success"}}' "$req"
gate 1 "one job skipped" \
  '{"test":{"result":"success"},"race":{"result":"success"},"docker-acceptance":{"result":"skipped"}}' "$req"
gate 1 "required job missing from needs" \
  '{"test":{"result":"success"},"race":{"result":"success"}}' "$req"
gate 1 "unknown result value" \
  '{"test":{"result":"success"},"race":{"result":"neutral"},"docker-acceptance":{"result":"success"}}' "$req"
gate 1 "result is not a string" \
  '{"test":{"result":true},"race":{"result":"success"},"docker-acceptance":{"result":"success"}}' "$req"
gate 1 "job entry has no result" \
  '{"test":{},"race":{"result":"success"},"docker-acceptance":{"result":"success"}}' "$req"
gate 1 "job entry is not an object" \
  '{"test":"success","race":{"result":"success"},"docker-acceptance":{"result":"success"}}' "$req"
gate 1 "empty NEEDS_JSON" "" "$req"
gate 1 "empty needs object" "{}" "$req"
gate 1 "NEEDS_JSON is not JSON" "not json" "$req"
gate 1 "NEEDS_JSON is not an object" '["success"]' "$req"
gate 1 "empty REQUIRED_JOBS" "$all_ok" ""
gate 1 "blank REQUIRED_JOBS" "$all_ok" "   "

rc=0
env -u NEEDS_JSON -u REQUIRED_JOBS scripts/ci-gate.sh >/dev/null 2>&1 || rc=$?
if [[ "$rc" -eq 1 ]]; then ok "gate: unset variables"; else bad "gate: unset variables (exit $rc, want 1)"; fi

# The summary may never change the verdict: exit 0 even when gh fails or
# returns rubbish, and print a table when it works. gh is faked on PATH.
mkdir "$tmp/ok" "$tmp/broken"
cat >"$tmp/ok/gh" <<'GH'
#!/usr/bin/env bash
case "$*" in
  *"/jobs"*)
    echo '{"name":"Go (ubuntu-latest)","status":"completed","conclusion":"success","created_at":"2026-01-01T10:00:00Z","started_at":"2026-01-01T10:00:03Z","completed_at":"2026-01-01T10:00:45Z"}'
    ;;
  *) echo '{"run_started_at":"2026-01-01T10:00:00Z"}' ;;
esac
GH
printf '#!/usr/bin/env bash\necho not json\nexit 1\n' >"$tmp/broken/gh"
chmod +x "$tmp/ok/gh" "$tmp/broken/gh"

summary() {
  GH_TOKEN=unused GITHUB_REPOSITORY=owner/repo GITHUB_RUN_ID=1 PATH="$1:$PATH" \
    scripts/ci-summary.sh 2>&1
}

rc=0
output="$(summary "$tmp/broken")" || rc=$?
if [[ "$rc" -eq 0 && "$output" == *"timing summary skipped"* ]]; then
  ok "summary: gh failure is reported with exit 0"
else
  bad "summary: gh failure is reported with exit 0 (exit $rc)"
fi
rc=0
output="$(env -u GITHUB_REPOSITORY -u GITHUB_RUN_ID scripts/ci-summary.sh 2>&1)" || rc=$?
if [[ "$rc" -eq 0 && "$output" == *"timing summary skipped"* ]]; then
  ok "summary: missing environment is reported with exit 0"
else
  bad "summary: missing environment is reported with exit 0 (exit $rc)"
fi
rc=0
output="$(summary "$tmp/ok")" || rc=$?
if [[ "$rc" -eq 0 && "$output" == *"| Go (ubuntu-latest) | 3s | 42s | success |"* &&
  "$output" == *"Wall-clock since run start"* ]]; then
  ok "summary: table lists job queue, duration and result"
else
  bad "summary: table lists job queue, duration and result (exit $rc)"
fi

# Structure of ci.yml, without a YAML parser.
words() { tr ', ' '\n\n' | sed '/^$/d' | sort -u; }
joined() { tr '\n' ' ' | sed 's/ $//'; }

all_jobs="$(awk '
  /^jobs:/ { in_jobs = 1; next }
  in_jobs && /^[^ #]/ { in_jobs = 0 }
  in_jobs && /^  [A-Za-z0-9_-]+: *$/ { sub(/^  /, ""); sub(/:.*$/, ""); print }
' "$workflow")"
gate_block="$(awk '
  /^  ci-gate: *$/ { on = 1; next }
  on && /^  [A-Za-z0-9_-]+: *$/ { on = 0 }
  on
' "$workflow")"
yaml_required="$(printf '%s\n' "$gate_block" | sed -n 's/^ *REQUIRED_JOBS: *"\(.*\)" *$/\1/p' | words)"
yaml_needs="$(printf '%s\n' "$gate_block" | sed -n 's/^    needs: *\[\(.*\)\] *$/\1/p' | words)"
other_jobs="$(printf '%s\n' "$all_jobs" | grep -vx 'ci-gate' | sort -u || true)"

if [[ -z "$gate_block" ]]; then
  bad "workflow: job ci-gate exists"
else
  ok "workflow: job ci-gate exists"
fi
if [[ -n "$yaml_required" && "$yaml_required" == "$yaml_needs" ]]; then
  ok "workflow: REQUIRED_JOBS equals needs of ci-gate ($(printf '%s\n' "$yaml_needs" | joined))"
else
  bad "workflow: REQUIRED_JOBS ($(printf '%s\n' "$yaml_required" | joined)) differs from needs of ci-gate ($(printf '%s\n' "$yaml_needs" | joined))"
fi
if [[ -n "$other_jobs" && "$yaml_needs" == "$other_jobs" ]]; then
  ok "workflow: ci-gate needs every other job"
else
  bad "workflow: ci-gate needs ($(printf '%s\n' "$yaml_needs" | joined)) differs from the other jobs ($(printf '%s\n' "$other_jobs" | joined))"
fi
if printf '%s\n' "$gate_block" | grep -Fxq '    if: always()'; then
  ok "workflow: ci-gate job runs with if: always()"
else
  bad "workflow: ci-gate job runs with if: always()"
fi
if printf '%s\n' "$gate_block" | grep -Fxq '        if: always()'; then
  ok "workflow: ci-gate summary step runs with if: always()"
else
  bad "workflow: ci-gate summary step runs with if: always()"
fi
if grep -v '^[[:space:]]*#' "$workflow" | grep -q 'continue-on-error'; then
  bad "workflow: no continue-on-error"
else
  ok "workflow: no continue-on-error"
fi
if grep -Fxq '    name: ci-gate' "$workflow" && grep -Fxq '    name: Go (${{ matrix.os }})' "$workflow"; then
  ok "workflow: required check names ci-gate and Go (os) are kept"
else
  bad "workflow: required check names ci-gate and Go (os) are kept"
fi

echo "$checks checks, $failures failed"
[[ "$failures" -eq 0 ]]
