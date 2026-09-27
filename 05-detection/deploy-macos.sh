#!/usr/bin/env bash
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/Applications/Splunk}"
APP="$SPLUNK_HOME/etc/apps/soc_capstone_detections"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$APP/local/data/ui/views" "$APP/metadata" "$APP/appserver/static" "$APP/default"
cp "$HERE/savedsearches.conf" "$APP/local/savedsearches.conf"
cp "$HERE/soc_capstone_dashboard.xml" "$APP/local/data/ui/views/soc_capstone_dashboard.xml"
cp "$HERE/../04-attacks/payload/soc_benign_payload.ps1" "$APP/appserver/static/soc_benign_payload.ps1"
printf '[permissions]\naccess = read\nexport = system\n' > "$APP/metadata/default.meta"
printf '[install]\nstate = enabled\n[ui]\nis_visible = true\n[label]\nname = SOC Playground Detections\n' > "$APP/default/app.conf"
if ! "$SPLUNK_HOME/bin/splunk" restart --no-prompt; then
  printf 'Files copied, but Splunk could not restart here. Restart Splunk from an unrestricted Mac terminal.\n' >&2
  exit 1
fi
printf 'Deployed Splunk app to %s\n' "$APP"
