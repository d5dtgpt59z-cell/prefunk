#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
binary="$project_dir/work/drop-provider-regression"
mkdir -p "$project_dir/work"

xcrun swiftc \
    -parse-as-library \
    "$project_dir/Tests/DropProviderRegression.swift" \
    -framework AppKit \
    -framework UniformTypeIdentifiers \
    -o "$binary"
"$binary"
