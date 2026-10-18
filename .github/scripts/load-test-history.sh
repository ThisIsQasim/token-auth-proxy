#!/usr/bin/env bash
# Appends p50 and p99 latency charts over the last runs to the job summary.
#
# The history is the load-test-report artifact of earlier successful CI
# runs on main (the current run's reports are read from the working
# directory), drawn as Mermaid xychart-beta blocks, which GitHub renders
# in a summary without any image to host. A run is skipped when its
# artifact has expired or lacks one of the scenarios.
#
# Needs: gh (GH_TOKEN, GH_REPO), jq, GITHUB_STEP_SUMMARY, GITHUB_RUN_ID,
# GITHUB_SHA, and actions: read on the token.
set -euo pipefail

runs=${HISTORY_RUNS:-10}
scenarios="baseline basic-auth jwt-auth jwt-acl"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Latencies are Go durations ("596.795µs", "1.04ms"); print milliseconds.
ms='capture("^(?<n>[0-9.]+)(?<u>.*)$")
  | (.n | tonumber) * ({"ns": 0.000001, "µs": 0.001, "μs": 0.001, "ms": 1, "s": 1000}[.u])
  | . * 1000 | round / 1000'

# dirs holds "<label> <directory>" lines, oldest first, current run last.
gh run list --workflow ci.yml --branch main --status success --limit $((runs * 2)) \
  --json databaseId,headSha \
  -q ".[] | select(.databaseId != ${GITHUB_RUN_ID}) | \"\(.databaseId) \(.headSha[0:7])\"" |
  head -n $((runs - 1)) | while read -r id sha; do
    gh run download "$id" -n load-test-report -D "$work/$id" >/dev/null 2>&1 || continue
    echo "$sha $work/$id"
  done | tac >"$work/dirs"
echo "${GITHUB_SHA:0:7} ." >>"$work/dirs"

# complete keeps only the runs that have a report for every scenario.
: >"$work/complete"
while read -r label dir; do
  ok=1
  for s in $scenarios; do
    [ -f "$dir/load-test-report-$s.json" ] || ok=0
  done
  [ "$ok" = 1 ] && echo "$label $dir" >>"$work/complete"
done <"$work/dirs"

if [ "$(wc -l <"$work/complete")" -lt 2 ]; then
  {
    echo "## Load Test History"
    echo ""
    echo "_Fewer than two runs with a complete report, nothing to chart yet._"
  } >>"$GITHUB_STEP_SUMMARY"
  exit 0
fi

value() { # value <dir> <scenario> <latency field>
  jq -r ".$3 | $ms" "$1/load-test-report-$2.json"
}

labels=$(awk '{printf "%s\"%s\"", sep, $1; sep=", "}' "$work/complete")

chart() { # chart <title> <field> <scenario>...
  title=$1
  field=$2
  shift 2
  echo '```mermaid'
  echo "xychart-beta"
  echo "    title \"$title\""
  echo "    x-axis [$labels]"
  echo '    y-axis "ms"'
  for s in "$@"; do
    line=""
    while read -r _ dir; do
      line="$line${line:+, }$(value "$dir" "$s" "$field")"
    done <"$work/complete"
    echo "    line [$line]"
  done
  echo '```'
  echo ""
}

{
  echo "## Load Test History"
  echo ""
  echo "Last $(wc -l <"$work/complete") runs on main, oldest first; the right-most point is this run."
  echo ""
  echo "**p50 latency**, lines in order: baseline, basic-auth, jwt-auth, jwt-acl"
  echo ""
  chart "p50 latency (ms)" latency_p50 baseline basic-auth jwt-auth jwt-acl
  echo "**p99 latency**, lines in order: baseline, jwt-auth, jwt-acl"
  echo ""
  chart "p99 latency (ms)" latency_p99 baseline jwt-auth jwt-acl
  echo "**basic-auth p99 latency** (bcrypt makes it far noisier, so it has its own scale)"
  echo ""
  chart "basic-auth p99 latency (ms)" latency_p99 basic-auth

  header="| Run"
  divider="|---"
  for s in $scenarios; do
    header="$header | $s p50 | $s p99"
    divider="$divider|---|---"
  done
  echo "<details><summary>Numbers (ms)</summary>"
  echo ""
  echo "$header |"
  echo "$divider|"
  while read -r label dir; do
    line="| $label"
    for s in $scenarios; do
      line="$line | $(value "$dir" "$s" latency_p50) | $(value "$dir" "$s" latency_p99)"
    done
    echo "$line |"
  done <"$work/complete"
  echo ""
  echo "</details>"
} >>"$GITHUB_STEP_SUMMARY"
