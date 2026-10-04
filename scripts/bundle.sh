#!/usr/bin/env bash
# Inlines lib/ui.sh into install.sh and uninstall.sh so they work through `curl | bash`.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p ../dist
for f in install.sh uninstall.sh; do
  awk '
    /^# @include lib\/ui.sh$/ {
      while ((getline line < "lib/ui.sh") > 0) print line
      skip = 2
      next
    }
    skip > 0 { skip--; next }
    { print }
  ' "$f" >"../dist/$f"
  chmod +x "../dist/$f"
done
echo "bundled: dist/install.sh dist/uninstall.sh"
