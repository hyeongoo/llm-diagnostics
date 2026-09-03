#!/bin/bash

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <SSH_HOST_ALIAS>"
    exit 1
fi

BASE_DIR="$HOME/aiops-openstack"
LOG_DIR="$BASE_DIR/logs"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT="$LOG_DIR/host_${TARGET}_${TIMESTAMP}.log"

ssh -T "$TARGET" 'bash -s' <<'REMOTE' > "$OUTPUT" 2>&1
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

echo
echo "===== RECENT ERRORS ====="
sudo journalctl -p err -n 50 --no-pager
REMOTE

echo "Collected: $OUTPUT"