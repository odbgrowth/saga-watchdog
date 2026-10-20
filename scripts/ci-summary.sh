#!/usr/bin/env bash
# Write a timing table for the current workflow run to the job summary:
# queue time, duration and result per job, plus wall-clock, critical path and
# runner seconds. Informational only: any problem is reported as a warning and
# the exit status is always 0, so this script can never change a CI verdict.
#
#   GH_TOKEN=... GITHUB_REPOSITORY=owner/repo GITHUB_RUN_ID=123 scripts/ci-summary.sh
#
# Needs gh and jq. Without GITHUB_STEP_SUMMARY the table goes to stdout.
set -euo pipefail

finish() {
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "::warning title=ci-summary::timing summary skipped (exit $rc); the ci-gate verdict is not affected"
  fi
  exit 0
}
trap finish EXIT

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
run_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID is not set}"
out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

run_json="$(timeout 30 gh api "repos/$repo/actions/runs/$run_id")"
jobs_json="$(timeout 60 gh api --paginate "repos/$repo/actions/runs/$run_id/jobs?per_page=100" --jq '.jobs[]' | jq -s '.')"
now="$(date -u +%s)"

# Build the whole table first, so a failure never leaves half a table behind.
table="$(jq -r --argjson run "$run_json" --argjson now "$now" '
  def t: if . == null then null else fromdateiso8601 end;
  def span($from; $to): if $from == null or $to == null then 0 else ($to | t) - ($from | t) end;
  def cell: tostring | gsub("\\|"; "\\|");
  map(. + {
    queue: span(.created_at; .started_at),
    dur: span(.started_at; (.completed_at // ($now | todate))),
    result: (.conclusion // .status)
  })
  | sort_by(.started_at // .created_at) as $jobs
  | ($jobs | map(select(.status == "completed")) | max_by(.dur)) as $crit
  | ($run.run_started_at // $run.created_at) as $start
  | [
      "### CI timing",
      "",
      "| Job | Queue | Duration | Result |",
      "|---|---:|---:|---|",
      ($jobs[] | "| \(.name | cell) | \(.queue)s | \(.dur)s | \(.result | cell) |"),
      "",
      "| Measure | Value |",
      "|---|---:|",
      "| Wall-clock since run start | \($now - ($start | t))s |",
      "| Critical path (longest finished job) | \(if $crit then "\($crit.name | cell), \($crit.dur)s" else "n/a" end) |",
      "| Runner seconds (sum of job durations) | \($jobs | map(.dur) | add // 0)s |",
      "",
      "A job that is still running (this one) is counted up to now."
    ]
  | join("\n")' <<<"$jobs_json")"

printf '%s\n' "$table" >>"$out"
