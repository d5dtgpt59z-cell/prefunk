#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
swift build --package-path "$project_dir" --product prefunk >/dev/null
binary="$project_dir/.build/debug/prefunk"

clean_output=$("$binary" scan "$project_dir/Tests/CLI-Fixtures/clean" --format json)
[[ "$?" -eq 0 ]]
print -r -- "$clean_output" | rg -q '"status" : "no_matches"'
print -r -- "$clean_output" | rg -q '"complete" : true'

markdown_output=$("$binary" scan "$project_dir/Tests/CLI-Fixtures/clean" \
    --format markdown --project-name "Client Safe Project")
[[ "$?" -eq 0 ]]
print -r -- "$markdown_output" | rg -q '^## Executive Summary$'
print -r -- "$markdown_output" | rg -q '^\*\*Project:\*\* Client Safe Project'
print -r -- "$markdown_output" | rg -q '^## Technical Details$'
if print -r -- "$markdown_output" | rg -q 'CLI-Fixtures/clean'; then
    echo "CLI contract failed: internal fixture path leaked to client Markdown." >&2
    exit 1
fi

named_json=$("$binary" scan "$project_dir/Tests/CLI-Fixtures/clean" \
    --format json --project-name "Client Safe Project")
print -r -- "$named_json" | rg -q '"projectLabel" : "Client Safe Project"'
if print -r -- "$named_json" | rg -q 'CLI-Fixtures/clean'; then
    echo "CLI contract failed: internal fixture path leaked to client agent JSON." >&2
    exit 1
fi

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
