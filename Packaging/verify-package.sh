#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
app_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$project_dir/Packaging/Info.plist")
archive_path=${1:-"$project_dir/outputs/Prefunk-${app_version}-macOS.zip"}
extract_dir=$(mktemp -d "${TMPDIR:-/tmp}/prefunk-package-verify.XXXXXX")
trap 'rm -rf "$extract_dir"' EXIT

[[ -f "$archive_path" ]] || {
    echo "Package verification failed: archive not found: $archive_path" >&2
    exit 1
}

unzip -tq "$archive_path" >/dev/null
if unzip -Z1 "$archive_path" | rg -q '(^|/)__MACOSX/|(^|/)\\._|\\.DS_Store$'; then
    echo "Package verification failed: archive contains Finder metadata." >&2
    exit 1
fi

ditto -x -k "$archive_path" "$extract_dir"
app_dir="$extract_dir/Prefunk.app"
app_binary="$app_dir/Contents/MacOS/Prefunk"
cli_binary="$app_dir/Contents/Resources/prefunk"
info_plist="$app_dir/Contents/Info.plist"

[[ -x "$app_binary" && -x "$cli_binary" && -f "$info_plist" ]] || {
    echo "Package verification failed: required app files are missing or not executable." >&2
    exit 1
}

packaged_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info_plist")
[[ "$packaged_version" == "$app_version" ]] || {
    echo "Package verification failed: packaged version is $packaged_version, expected $app_version." >&2
    exit 1
}

codesign --verify --deep --strict "$app_dir"
entitlements="$extract_dir/entitlements.plist"
codesign -d --entitlements :- "$app_dir" >"$entitlements" 2>/dev/null
/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "$entitlements" | rg -q '^true$'
/usr/libexec/PlistBuddy -c 'Print :com.apple.security.files.user-selected.read-only' "$entitlements" | rg -q '^true$'
if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.files.user-selected.read-write' "$entitlements" >/dev/null 2>&1; then
    echo "Package verification failed: packaged app has read-write project access." >&2
    exit 1
fi

scan_output="$extract_dir/scan.json"
"$cli_binary" scan "$project_dir/Tests/CLI-Fixtures/clean" --format json \
    --project-name "Packaged Verification" --output "$scan_output"
python3 - "$scan_output" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
assert report["projectLabel"] == "Packaged Verification"
assert report["status"] == "no_matches"
assert report["coverage"]["complete"] is True
assert report["findings"] == []
PY

if [[ "${REQUIRE_PUBLIC_SIGNATURE:-0}" == "1" ]]; then
    signature_info=$(codesign -dv "$app_dir" 2>&1)
    if ! print -r -- "$signature_info" | rg -q 'Authority=Developer ID Application'; then
        echo "Public package verification failed: a downloadable ZIP requires Developer ID Application signing." >&2
        exit 1
    fi
    xcrun stapler validate "$app_dir"
fi

echo "Package verification passed: archive, metadata, signature, sandbox, and bundled CLI."
