#!/bin/bash

BASE_DIR="$HOME/aiops-openstack"
LOG_DIR="$BASE_DIR/logs"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT="$LOG_DIR/openstack_${TIMESTAMP}.log"

{
    echo "===== TIMESTAMP ====="
    date

    echo
    echo "===== SERVERS ====="
    openstack server list

    echo
    echo "===== NETWORKS ====="
    openstack network list

    echo
    echo "===== ROUTERS ====="
    openstack router list

    echo
    echo "===== VOLUMES ====="
    openstack volume list

    echo
    echo "===== LOAD BALANCERS ====="
    openstack loadbalancer list

    echo
    echo "===== AMPHORAE ====="
    openstack loadbalancer amphora list

} > "$OUTPUT" 2>&1

echo "Collected: $OUTPUT"