#!/usr/bin/env python3

import glob
import json
import os
import sys

from llm_client import build_prompt, call_ollama
from observations import (
    build_observation_catalog,
    build_observation_map,
)
from report import (
    build_report,
    save_analysis,
    save_llm_trace,
)
from schema import build_response_schema
from service_detail import collect_service_detail
from targets import (
    build_analysis_targets,
    load_targets,
)
from validation import validate_response


BASE_DIR = os.path.expanduser("~/aiops-openstack")
LOG_DIR = os.path.join(BASE_DIR, "logs")


def main():
    configured_targets = (
        load_targets()
    )

    anomaly_files = glob.glob(
        os.path.join(
            LOG_DIR,
            "anomaly_*.json"
        )
    )

    if not anomaly_files:
        print(
            "No anomaly result found."
        )
        sys.exit(1)

    latest_anomaly = max(
        anomaly_files,
        key=os.path.getmtime
    )

    with open(
        latest_anomaly,
        "r",
        encoding="utf-8"
    ) as f:
        anomaly_result = json.load(
            f
        )

    if (
        anomaly_result.get(
            "status"
        )
        != "ANOMALY"
    ):
        print(
            "No anomaly detected. "
            "AI analysis skipped."
        )
        sys.exit(0)

    latest_log = anomaly_result.get(
        "diagnostic_file"
    )

    if (
        not latest_log
        or not os.path.exists(
            latest_log
        )
    ):
        print(
            "Diagnostic log referenced by "
            "anomaly result not found."
        )
        sys.exit(1)

    findings = anomaly_result.get(
        "findings",
        []
    )

    targets = build_analysis_targets(
        findings,
        configured_targets
    )

    if not targets:
        print(
            "No analysis target found."
        )
        sys.exit(1)

    results = {}
    detail_cache = {}

    for target in targets:
        finding_id = target[
            "finding_id"
        ]

        host = target[
            "host"
        ]

        service = target[
            "service"
        ]

        cache_key = (
            host,
            service
        )

        if (
            cache_key
            not in detail_cache
        ):
            detail_path = (
                collect_service_detail(
                    host,
                    service
                )
            )

            with open(
                detail_path,
                "r",
                encoding="utf-8"
            ) as f:
                detail_data = f.read()

            detail_cache[
                cache_key
            ] = (
                detail_path,
                detail_data
            )

        else:
            (
                detail_path,
                detail_data
            ) = detail_cache[
                cache_key
            ]

        print(
            "Detail     : "
            f"{host} / "
            f"{service} -> "
            f"{detail_path}"
        )

        observations = (
            build_observation_catalog(
                target[
                    "confirmed_fact"
                ],
                detail_data
            )
        )

        observation_map = (
            build_observation_map(
                observations
            )
        )

        analysis_input = {
            "finding_id":
                finding_id,

            "finding_type":
                target[
                    "type"
                ],

            "host":
                host,

            "service":
                service,

            "observations":
                observations,
        }

        raw_response = call_ollama(
            build_prompt(
                analysis_input
            ),
            build_response_schema(
                finding_id,
                list(
                    observation_map.keys()
                )
            ),
        )

        validated = (
            validate_response(
                raw_response,
                finding_id,
                observation_map
            )
        )

        results[
            finding_id
        ] = {
            "host":
                host,

            "service":
                service,

            "observations":
                observations,

            "observation_map":
                observation_map,

            "raw_response":
                raw_response,

            "validated":
                validated,
        }

    (
        analysis,
        trace_entries
    ) = build_report(
        targets,
        results
    )

    trace_output = save_llm_trace(
        trace_entries,
        latest_log,
        latest_anomaly,
        LOG_DIR
    )

    output = save_analysis(
        analysis,
        LOG_DIR
    )

    print(
        f"Diagnostic : {latest_log}"
    )

    print(
        f"Detection  : {latest_anomaly}"
    )

    print(
        f"Trace      : {trace_output}"
    )

    print(
        f"Output     : {output}"
    )

    print()

    print(
        analysis
    )


if __name__ == "__main__":
    main()