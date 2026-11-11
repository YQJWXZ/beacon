#!/usr/bin/env bash
# Install the beacon agent on this host.
#
#   sudo ./scripts/install.sh [path-to-beacon-binary]
#
# Idempotent: re-running upgrades the binary and keeps the existing config.
set -euo pipefail

BIN=${1:-./bin/beacon}
UNIT=deploy/beacon-agent.service
CONFIG=examples/agent.yaml

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi
if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi

install -m 0755 "$BIN" /usr/local/bin/beacon
install -d -m 0750 /etc/beacon
install -d -m 0700 /var/lib/beacon

if [[ ! -f /etc/beacon/agent.yaml ]]; then
  install -m 0640 "$CONFIG" /etc/beacon/agent.yaml
  echo "wrote /etc/beacon/agent.yaml (edit transport.endpoint and token)"
fi

install -m 0644 "$UNIT" /etc/systemd/system/beacon-agent.service
systemctl daemon-reload
systemctl enable --now beacon-agent.service

echo
echo "installed. next steps:"
echo "  1. beacon agent enroll -server http://<center>:8080 -token <enroll-token> -config /etc/beacon/agent.yaml"
echo "  2. edit /etc/beacon/agent.yaml: set transport.endpoint"
echo "  3. systemctl restart beacon-agent && beacon transport test -config /etc/beacon/agent.yaml"
