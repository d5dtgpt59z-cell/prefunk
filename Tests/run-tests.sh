#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
test_binary="$project_dir/work/scanner-regression"
mkdir -p "$project_dir/work"

xcrun swiftc \
    "$project_dir/Sources/PrefunkCore/Models.swift" \
    "$project_dir/Sources/PrefunkCore/Scanner.swift" \
    "$project_dir/Sources/PrefunkCore/AgentReport.swift" \
    "$project_dir/Tests/ScannerRegression.swift" \
    -o "$test_binary"
"$test_binary"
"$project_dir/Tests/privacy-invariant.sh"
"$project_dir/Tests/cli-contract.sh"
"$project_dir/Tests/release-invariant.sh"
python3 "$project_dir/Tests/plugin-invariant.py"
"$project_dir/Tests/ui-invariant.sh"
"$project_dir/Tests/drop-provider-test.sh"
