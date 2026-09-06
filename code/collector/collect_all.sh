#!/bin/bash
set -euo pipefail

BASE_DIR="$HOME/aiops-openstack"
LOG_DIR="$BASE_DIR/logs"
TARGETS_FILE="$BASE_DIR/config/targets.txt"

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
BUNDLE_LOG="$LOG_DIR/diagnostic_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

if [ ! -f "$TARGETS_FILE" ]; then
    echo "Targets file not found: $TARGETS_FILE"
    exit 1
fi


# OpenStack 상태 수집
if ! OPENSTACK_RESULT=$("$BASE_DIR/collector/collect_openstack.sh"); then
    echo "OpenStack collection failed."
    exit 1
fi

echo "$OPENSTACK_RESULT"

OPENSTACK_LOG="${OPENSTACK_RESULT#Collected: }"

if [ ! -f "$OPENSTACK_LOG" ]; then
    echo "OpenStack log not found: $OPENSTACK_LOG"
    exit 1
fi


# VM 상태 수집
HOST_TARGETS=()
HOST_LOGS=()
TARGET_COUNT=0

while IFS= read -r TARGET; do
    [[ -z "$TARGET" || "$TARGET" =~ ^# ]] && continue

    TARGET_COUNT=$((TARGET_COUNT + 1))

    if ! HOST_RESULT=$(
        "$BASE_DIR/collector/collect_host.sh" "$TARGET"
    ); then
        echo "Host collection failed: $TARGET"
        exit 1
    fi

    echo "$HOST_RESULT"

    HOST_LOG="${HOST_RESULT#Collected: }"

    if [ ! -f "$HOST_LOG" ]; then
        echo "Host log not found: $HOST_LOG"
        exit 1
    fi

    HOST_TARGETS+=("$TARGET")
    HOST_LOGS+=("$HOST_LOG")

done < "$TARGETS_FILE"


if [ "$TARGET_COUNT" -eq 0 ]; then
    echo "No monitoring targets defined."
    exit 1
fi


# Diagnostic 통합
{
    echo "===== OPENSTACK STATUS ====="
    cat "$OPENSTACK_LOG"

    for i in "${!HOST_LOGS[@]}"; do
        echo
        echo "===== HOST STATUS: ${HOST_TARGETS[$i]} ====="
        cat "${HOST_LOGS[$i]}"
    done

} > "$BUNDLE_LOG"


echo "Diagnostic bundle: $BUNDLE_LOG"