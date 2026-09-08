#!/usr/bin/env python3

import os
import subprocess
import sys


BASE_DIR = os.path.expanduser("~/aiops-openstack")
SERVICE_DETAIL_COLLECTOR = os.path.join(
    BASE_DIR,
    "collector",
    "collect_service_detail.sh"
)


def collect_service_detail(
    host,
    service
):
    if not os.path.exists(
        SERVICE_DETAIL_COLLECTOR
    ):
        print(
            "Service detail collector "
            "not found: "
            f"{SERVICE_DETAIL_COLLECTOR}"
        )
        sys.exit(1)

    try:
        result = subprocess.run(
            [
                SERVICE_DETAIL_COLLECTOR,
                host,
                service
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

    except subprocess.TimeoutExpired:
        print(
            "Service detail collection "
            "timed out: "
            f"{host} / {service}"
        )
        sys.exit(1)

    except OSError as e:
        print(
            "Failed to execute service "
            "detail collector: "
            f"{e}"
        )
        sys.exit(1)

    if result.returncode != 0:
        print(
            "Service detail collection "
            "failed: "
            f"{host} / {service}"
        )

        if result.stderr.strip():
            print(
                result.stderr.strip()
            )

        sys.exit(1)

    detail_path = None

    for line in result.stdout.splitlines():
        if line.startswith(
            "Collected: "
        ):
            detail_path = (
                line[
                    len("Collected: "):
                ].strip()
            )

    if (
        not detail_path
        or not os.path.exists(
            detail_path
        )
    ):
        print(
            "Service detail log "
            "not found: "
            f"{detail_path or service}"
        )
        sys.exit(1)

    return detail_path