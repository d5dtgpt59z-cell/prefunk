#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
model="$project_dir/Sources/PrefunkMac/AppModel.swift"
view="$project_dir/Sources/PrefunkMac/ContentView.swift"

rg -q 'func startNewScan\(\)' "$model"
rg -q 'func handleDrop\(providers: \[NSItemProvider\]\)' "$model"
rg -q 'startAccessingSecurityScopedResource' "$model"
rg -q 'Button\(action: model.startNewScan\)' "$view"
rg -q '\.onDrop\(' "$view"
rg -q 'UTType\.fileURL' "$view"

if rg -q '\.dropDestination\(for: URL\.self\)' "$view"; then
    echo "UI invariant failed: fragile URL dropDestination returned." >&2
    exit 1
fi

echo "UI invariants passed: New Scan and Finder folder drop are wired."
