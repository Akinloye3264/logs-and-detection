#!/usr/bin/env bash
# Copies the solution decoders and rules into the Wazuh manager and validates them.
# Run on the Wazuh manager as root:  sudo ./scripts/deploy-solutions.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEC_DIR=/var/ossec/etc/decoders
RULE_DIR=/var/ossec/etc/rules

for f in "$REPO_DIR"/solutions/decoders/*.xml; do
  install -m 660 -o root -g wazuh "$f" "$DEC_DIR/$(basename "$f")"
  echo "Installed decoder: $(basename "$f")"
done

for f in "$REPO_DIR"/solutions/rules/*.xml; do
  install -m 660 -o root -g wazuh "$f" "$RULE_DIR/$(basename "$f")"
  echo "Installed rules:   $(basename "$f")"
done

echo "Validating configuration..."
/var/ossec/bin/wazuh-analysisd -t
echo "OK. Restart to apply to the live manager:  systemctl restart wazuh-manager"
