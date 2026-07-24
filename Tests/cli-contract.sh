#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
swift build --package-path "$project_dir" --product prefunk >/dev/null
binary="$project_dir/.build/debug/prefunk"

clean_output=$("$binary" scan "$project_dir/Tests/CLI-Fixtures/clean" --format json)
[[ "$?" -eq 0 ]]
print -r -- "$clean_output" | rg -q '"status" : "no_matches"'
print -r -- "$clean_output" | rg -q '"complete" : true'

set +e
finding_output=$("$binary" scan "$project_dir/Tests/CLI-Fixtures/finding" --format json)
finding_status=$?
set -e
[[ "$finding_status" -eq 2 ]]
print -r -- "$finding_output" | rg -q '"status" : "potential_findings"'
if print -r -- "$finding_output" | rg -q -- '-----BEGIN OPENSSH PRIVATE KEY-----'; then
    echo "CLI contract failed: secret leaked to JSON." >&2
    exit 1
fi

echo "CLI contract passed: clean=0, findings=2, output redacted."
