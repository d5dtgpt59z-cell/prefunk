#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
cd "$project_dir"

app_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Packaging/Info.plist)
engine_version=$(sed -n 's/.*scannerVersion = "\([^"]*\)".*/\1/p' Sources/PrefunkCore/Models.swift)
[[ "$app_version" == "$engine_version" ]] || {
    echo "Version mismatch: app=$app_version engine=$engine_version" >&2
    exit 1
}

rg -q 'com.apple.security.files.user-selected.read-only' Packaging/Prefunk.entitlements
if rg -q 'read-write' Packaging/Prefunk.entitlements; then
    echo "Release invariant failed: project access is read-write." >&2
    exit 1
fi
if [[ -e plugins/prefunk/.mcp.json ]]; then
    echo "Release invariant failed: MVP must not expose MCP." >&2
    exit 1
fi
if rg -q 'command -v prefunk|exec prefunk ' plugins/prefunk/scripts/prefunk-scan; then
    echo "Release invariant failed: plugin launcher trusts PATH." >&2
    exit 1
fi
rg -q 'PREFUNK_ALLOW_DEV_OVERRIDE' plugins/prefunk/scripts/prefunk-scan
[[ -x Packaging/verify-package.sh ]] || {
    echo "Release invariant failed: package verifier is missing or not executable." >&2
    exit 1
}
rg -q 'verify-package\.sh' Packaging/package.sh
if rg -q '\\$1\\.99|early preview|This preview' README.md; then
    echo "Release invariant failed: stale paid-preview language remains in README." >&2
    exit 1
fi

echo "Release invariants passed: versions aligned, read-only, no MCP, trusted launcher order, package verification wired."
