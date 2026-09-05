#!/bin/bash

set -euo pipefail

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <SSH_HOST_ALIAS>"
    exit 1
fi

BASE_DIR="$HOME/aiops-openstack"
LOG_DIR="$BASE_DIR/logs"
DESIRED_STATE_FILE="$BASE_DIR/config/desired_state.json"

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT="$LOG_DIR/host_${TARGET}_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

if [ ! -f "$DESIRED_STATE_FILE" ]; then
    echo "Desired State file not found: $DESIRED_STATE_FILE"
    exit 1
fi

# Desired State에 정의된 서비스 목록 읽기
if ! SERVICE_LIST=$(python3 - "$DESIRED_STATE_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    desired_state = json.load(f)

for service in desired_state.get("services", {}):
    print(service)
PY
); then
    echo "Failed to read Desired State."
    exit 1
fi

SERVICES=()

if [ -n "$SERVICE_LIST" ]; then
    mapfile -t SERVICES <<< "$SERVICE_LIST"
fi

ssh -T "$TARGET" 'bash -s' <<'REMOTE' > "$OUTPUT" 2>&1
set -e

echo "===== HOSTNAME ====="
hostname

echo
echo "===== UPTIME ====="
uptime

echo
echo "===== MEMORY ====="
free -h

echo
echo "===== DISK ====="
df -h

echo
echo "===== FAILED SERVICES ====="
systemctl --failed --no-pager
REMOTE

# Desired State에 정의된 서비스 상태 수집
for SERVICE in "${SERVICES[@]}"; do
    SERVICE_LABEL=$(echo "$SERVICE" | tr '[:lower:]' '[:upper:]')

    if SERVICE_STATUS=$(ssh -T "$TARGET" "systemctl is-active '$SERVICE'" 2>&1); then
        STATUS_CODE=0
    else
        STATUS_CODE=$?
    fi

    # SSH 자체가 실패한 경우 수집 중단
    if [ "$STATUS_CODE" -eq 255 ]; then
        echo "SSH connection failed while checking service: $SERVICE"
        exit 1
    fi

    {
        echo
        echo "===== ${SERVICE_LABEL} STATUS ====="
        echo "$SERVICE_STATUS"
    } >> "$OUTPUT"
done

ssh -T "$TARGET" 'bash -s' <<'REMOTE' >> "$OUTPUT" 2>&1
set -e

echo
echo "===== RECENT ERRORS ====="
sudo journalctl -p err -n 50 --no-pager
REMOTE

echo "Collected: $OUTPUT"