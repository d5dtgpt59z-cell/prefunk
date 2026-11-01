#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
output_dir="$project_dir/outputs"
signing_identity=${SIGNING_IDENTITY:--}
app_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$project_dir/Packaging/Info.plist")
archive_name="Prefunk-${app_version}-macOS.zip"
archive_path="$output_dir/$archive_name"
stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/prefunk-package.XXXXXX")
app_dir="$stage_dir/Prefunk.app"
trap 'rm -rf "$stage_dir"' EXIT

cd "$project_dir"
"$project_dir/Tests/run-tests.sh"
swift build -c release

mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
cp ".build/release/PrefunkMac" "$app_dir/Contents/MacOS/Prefunk"
cp ".build/release/prefunk" "$app_dir/Contents/Resources/prefunk"
cp "Packaging/Info.plist" "$app_dir/Contents/Info.plist"
cp "Assets/AppIcon.icns" "$app_dir/Contents/Resources/AppIcon.icns"

xattr -cr "$app_dir"
codesign --force --deep --options runtime \
    --entitlements "Packaging/Prefunk.entitlements" \
    --sign "$signing_identity" "$app_dir"

mkdir -p "$output_dir"
rm -f "$archive_path"
(
    cd "$stage_dir"
    COPYFILE_DISABLE=1 zip -qry -X "$archive_path" "Prefunk.app"
)

"$project_dir/Packaging/verify-package.sh" "$archive_path"
echo "$archive_path"
