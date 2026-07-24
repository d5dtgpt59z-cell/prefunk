#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
output_dir="$project_dir/outputs"
app_dir="$output_dir/Prefunk.app"
signing_identity=${SIGNING_IDENTITY:--}

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

rm -f "$output_dir/Prefunk-macOS.zip"
(
    cd "$output_dir"
    COPYFILE_DISABLE=1 zip -qry -X "Prefunk-macOS.zip" "Prefunk.app"
)

echo "$app_dir"
