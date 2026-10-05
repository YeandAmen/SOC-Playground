# 05 - Detection (SPL saved searches + dashboard)

Use `bash 05-detection/deploy-macos.sh` from the repository root to deploy
these files and the benign payload to the local Splunk installation. The
separate live console is in `07-live-console/`.

## Deploy on the Splunk manager (this Mac)
```bash
APP=/Applications/Splunk/etc/apps/soc_capstone_detections
sudo mkdir -p "$APP"/{local,metadata}
sudo cp savedsearches.conf "$APP/local/"
sudo cp soc_capstone_dashboard.xml "$APP/local/data/ui/views/soc_capstone_dashboard.xml" 2>/dev/null \
  || { sudo mkdir -p "$APP/local/data/ui/views"; sudo cp soc_capstone_dashboard.xml "$APP/local/data/ui/views/soc_capstone_dashboard.xml"; }
# grant read to everyone in the lab
echo -e "[permissions]\naccess = read\nexport = system" | sudo tee "$APP/metadata/default.meta" >/dev/null
/Applications/Splunk/bin/splunk restart
```

## Local detection status

`detection/scan.py` writes `detection/status.json` for the live console status
tags. That JSON is generated from the clone owner's Splunk data and is ignored
by git.

```bash
SPLUNK_PASSWORD='your-local-password' python3 detection/scan.py
SPLUNK_PASSWORD='your-local-password' python3 detection/scan.py --watch
```

Use `SPLUNK_USER` and `SPLUNK_BIN` if your Splunk account or binary path differs.

Then open **Settings → Searches, reports, and alerts** (saved searches) and
**Dashboards → SOC Playground — Attack Detection Dashboard**.

## Why these are real detections, not raw searches
- Each search filters to the dedicated `soc_capstone` index + correct sourcetype,
  groups by the attacker-attributable field (source IP / account / process), and
  applies a threshold — the same shape a production correlation rule uses.
- Packaged as `savedsearches.conf` (importable, version-controllable) + a
  dashboard XML, so "proof of ingestion" is a real SOC-style dashboard, not
  `index=* | head 10`.
- Event IDs used: 4624/4625 (logon), 4720/4728/4732 (account/group), Sysmon
  1 (proc create), 3 (network), 4 (state change), 1102 (log cleared).
