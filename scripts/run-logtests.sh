#!/usr/bin/env bash
# Replays every sample log through wazuh-logtest so you can eyeball the results.
# Each file is sent in ONE session, so frequency rules can accumulate.
# Run on the Wazuh manager:  sudo ./scripts/run-logtests.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

for f in "$REPO_DIR"/exercises/*/*-logs.txt; do
  echo
  echo "=================================================="
  echo "  $(basename "$(dirname "$f")") / $(basename "$f")"
  echo "=================================================="
  /var/ossec/bin/wazuh-logtest < "$f"
done
