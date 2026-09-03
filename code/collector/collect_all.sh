#!/bin/bash

BASE_DIR="$HOME/aiops-openstack"
LOG_DIR="$BASE_DIR/logs"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

OPENSTACK_LOG="$LOG_DIR/openstack_${TIMESTAMP}.log"
HOST_LOG="$LOG_DIR/host_aiops-server_${TIMESTAMP}.log"
BUNDLE_LOG="$LOG_DIR/diagnostic_${TIMESTAMP}.log"

"$BASE_DIR/collector/collect_openstack.sh"

LATEST_OPENSTACK=$(ls -t "$LOG_DIR"/openstack_*.log | head -1)
cp "$LATEST_OPENSTACK" "$OPENSTACK_LOG"

"$BASE_DIR/collector/collect_host.sh" aiops-server

LATEST_HOST=$(ls -t "$LOG_DIR"/host_aiops-server_*.log | head -1)
cp "$LATEST_HOST" "$HOST_LOG"

{
    echo "===== OPENSTACK STATUS ====="
    cat "$OPENSTACK_LOG"

    echo
    echo "===== INSTANCE2 STATUS ====="
    cat "$HOST_LOG"
} > "$BUNDLE_LOG"

echo "Diagnostic bundle: $BUNDLE_LOG"