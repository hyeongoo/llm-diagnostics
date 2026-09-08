#!/usr/bin/env python3

import os
import sys


BASE_DIR = os.path.expanduser("~/aiops-openstack")
TARGETS_FILE = os.path.join(
    BASE_DIR,
    "config",
    "targets.txt"
)


def load_targets():
    if not os.path.exists(TARGETS_FILE):
        print(
            f"Targets file not found: "
            f"{TARGETS_FILE}"
        )
        sys.exit(1)

    with open(
        TARGETS_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        targets = [
            line.strip()
            for line in f
            if (
                line.strip()
                and not line.strip().startswith("#")
            )
        ]

    if not targets:
        print(
            "No monitoring target defined."
        )
        sys.exit(1)

    return targets


def resolve_target(
    finding,
    configured_targets
):
    target = finding.get(
        "target"
    )

    if target:
        if target not in configured_targets:
            print(
                "Finding references an "
                "unknown target: "
                f"{target}"
            )
            sys.exit(1)

        return target

    if len(configured_targets) == 1:
        return configured_targets[0]

    print(
        "Unable to determine target host "
        "for anomaly finding."
    )
    sys.exit(1)


def build_analysis_targets(
    findings,
    configured_targets
):
    targets = []
    number = 1

    for finding in findings:
        host = resolve_target(
            finding,
            configured_targets
        )

        finding_type = finding.get(
            "type"
        )

        if (
            finding_type
            == "service_state_mismatch"
        ):
            service = finding.get(
                "service"
            )

            if service:
                targets.append({
                    "finding_id":
                        f"F{number}",

                    "type":
                        finding_type,

                    "host":
                        host,

                    "service":
                        service,

                    "confirmed_fact": (
                        f"expected="
                        f"{finding.get('expected')}, "
                        f"actual="
                        f"{finding.get('actual')}"
                    ),
                })

                number += 1

        elif (
            finding_type
            == "failed_services_exceeded"
        ):
            for service in finding.get(
                "services",
                []
            ):
                targets.append({
                    "finding_id":
                        f"F{number}",

                    "type":
                        "failed_service",

                    "host":
                        host,

                    "service":
                        service,

                    "confirmed_fact":
                        "systemctl --failed에 포함됨",
                })

                number += 1

    return targets