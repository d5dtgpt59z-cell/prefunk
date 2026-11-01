#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
for forbidden in URLSession "import Network" NWConnection Analytics Telemetry "Process(" NSTask \
    "curl " "wget " "http://" "https://"; do
    if rg -n -F "$forbidden" "$project_dir/Sources" "$project_dir/plugins"; then
        echo "Privacy invariant failed: network, telemetry, or process execution API found." >&2
        exit 1
    fi
done
echo "Privacy invariant passed: no network, telemetry, or process execution APIs found."
