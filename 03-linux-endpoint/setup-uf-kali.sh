#!/usr/bin/env bash
# 03-linux-endpoint / setup-uf-kali.sh
# Installs the Splunk Universal Forwarder on Kali (attacker + monitored Linux
# endpoint). Forwards /var/log/auth.log + /var/log/syslog to the Mac indexer.
#
# Kali is Debian-based, so we use the .deb. Auto-detects amd64 vs arm64 and
# pulls the pinned UF 10.4.3 build from Splunk downloads.
#
# Run as root on the Kali VM:
#   sudo bash setup-uf-kali.sh
set -euo pipefail

: "${SPLUNK_HOST_IP:?Set SPLUNK_HOST_IP to the Mac/Splunk IP reachable from this VM}"
RECEIVE_PORT="${SPLUNK_RECEIVE_PORT:-9997}"
INDEX_NAME="${SPLUNK_INDEX:-soc_capstone}"
UF_VERSION="10.4.3"
UF_BUILD="4174a2deda5d"
UF_HOME="/opt/splunkforwarder"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[X] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
if ! command -v wget >/dev/null; then
  apt-get update
  apt-get install -y wget
fi

# --- pick arch-appropriate .deb ------------------------------------------------
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  amd64)  DEB_URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/splunkforwarder-${UF_VERSION}-${UF_BUILD}-linux-amd64.deb" ;;
  arm64)  DEB_URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/splunkforwarder-${UF_VERSION}-${UF_BUILD}-linux-arm64.deb" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
DEB_FILE="/tmp/splunkforwarder.deb"

log "Target indexer : $SPLUNK_HOST_IP:$RECEIVE_PORT"
log "Arch / package : $ARCH -> $DEB_URL"
log "Downloading UF ${UF_VERSION}..."
wget -q -O "$DEB_FILE" "$DEB_URL" || die "download failed"

log "Installing .deb..."
dpkg -i "$DEB_FILE" || apt-get install -f -y

# --- outputs.conf : where to send ---------------------------------------------
log "Writing outputs.conf..."
mkdir -p "$UF_HOME/etc/system/local"
cat > "$UF_HOME/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = soc_lab
disabled = false

[tcpout:soc_lab]
server = $SPLUNK_HOST_IP:$RECEIVE_PORT

[tcpout:indexedredirect]
index = $INDEX_NAME
EOF

# --- inputs.conf : what to collect (auth.log + syslog) ------------------------
# auth.log  -> SSH password attempts (Failed password), sudo, su, useradd (Attk102 on Linux)
# syslog    -> general system activity timeline
log "Writing inputs.conf..."
cat > "$UF_HOME/etc/system/local/inputs.conf" <<EOF
[monitor:///var/log/auth.log]
disabled = false
index = $INDEX_NAME
sourcetype = linux_secure

[monitor:///var/log/syslog]
disabled = false
index = $INDEX_NAME
sourcetype = syslog
EOF

# --- accept license + start as the splunk user the deb created ----------------
log "Accepting UF license + starting..."
"$UF_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt >/tmp/uf-start.log 2>&1 \
  || { tail -n 20 /tmp/uf-start.log >&2; die "UF start failed"; }

# --- boot-start (systemd on Kali) ---------------------------------------------
# Run boot-start as root (the dpkg created a 'splunk' system user). We let
# Splunk manage the user; if a dedicated user is desired, create it first.
"$UF_HOME/bin/splunk" enable boot-start -systemd-managed 2>/dev/null \
  || "$UF_HOME/bin/splunk" enable boot-start 2>/dev/null || warn "enable boot-start skipped"

# --- final check --------------------------------------------------------------
sleep 3
log "UF status:"
"$UF_HOME/bin/splunk" status 2>&1 | sed 's/^/    /'
log "Receiver reachability:"
if nc -z -w3 "$SPLUNK_HOST_IP" "$RECEIVE_PORT" 2>/dev/null; then
  echo "    OK: $SPLUNK_HOST_IP:$RECEIVE_PORT reachable"
else
  echo "    FAIL: cannot reach $SPLUNK_HOST_IP:$RECEIVE_PORT — check Mac receiver / firewall"
fi

cat <<EOF

Kali UF is forwarding:
   /var/log/auth.log  -> $SPLUNK_HOST_IP:$RECEIVE_PORT  index=$INDEX_NAME
   /var/log/syslog    -> $SPLUNK_HOST_IP:$RECEIVE_PORT  index=$INDEX_NAME
EOF
