#!/usr/bin/env python3

import json
import os
from datetime import datetime


DATA_SOURCE_LABELS = {
    "rule_finding": "Rule Engine 탐지 결과",
    "systemctl_show": "systemctl show",
    "systemctl_status": "systemctl status",
    "service_journal": "서비스 journal",
}


def merge_refs(
    *groups
):
    merged = []

    for group in groups:
        for ref in group:
            if ref not in merged:
                merged.append(
                    ref
                )

    return merged


def compact_text(
    value,
    max_chars=180
):
    """
    운영자용 출력만 짧게 만들고,
    상세 원문은 Trace에 그대로 남긴다.
    """

    text = " ".join(
        str(value).split()
    )

    if len(text) <= max_chars:
        return text

    return (
        text[:max_chars].rstrip()
        + "..."
    )


def build_report(
    targets,
    results
):
    report_lines = [
        "## 진단 결과",
        "- 상태: ANOMALY",
    ]

    trace_entries = []

    for target in targets:
        finding_id = target[
            "finding_id"
        ]

        result = results[
            finding_id
        ]

        host = result[
            "host"
        ]

        service = result[
            "service"
        ]

        observation_map = result[
            "observation_map"
        ]

        validated = result[
            "validated"
        ]

        mechanism = validated[
            "failure_mechanism"
        ]

        causes = validated[
            "cause_candidates"
        ]

        checks = validated[
            "checks"
        ]

        remediation = validated[
            "remediation_candidates"
        ]

        # 상세 Observation / LLM 원본 / 검증 결과는
        # Trace에 그대로 보존한다.
        trace_entries.append({
            "finding_id":
                finding_id,

            "host":
                host,

            "service":
                service,

            "observations":
                result[
                    "observations"
                ],

            "llm_response":
                result[
                    "raw_response"
                ],

            "validated_result":
                validated,
        })

        report_lines.extend([
            "",
            f"### {host} / {service}",
            "",
            "핵심 근거",
        ])

        key_refs = validated[
            "selected_observations"
        ]

        # LLM이 selected_observations를 비운 경우에는
        # 실제 분석에서 사용한 Observation으로 대체한다.
        if not key_refs:
            fallback_refs = []

            if mechanism:
                fallback_refs.extend(
                    mechanism[
                        "observation_refs"
                    ]
                )

            for item in causes:
                fallback_refs.extend(
                    item[
                        "observation_refs"
                    ]
                )

            key_refs = merge_refs(
                fallback_refs
            )

        if key_refs:
            for ref in key_refs:
                observation = (
                    observation_map[
                        ref
                    ]
                )

                source = (
                    DATA_SOURCE_LABELS.get(
                        observation[
                            "source"
                        ],
                        observation[
                            "source"
                        ]
                    )
                )

                report_lines.append(
                    f"- [{source}] "
                    f"{compact_text(observation['content'])}"
                )

        else:
            report_lines.append(
                "- 핵심 근거 선택 없음"
            )

        report_lines.extend([
            "",
            "AI 판단",
        ])

        if mechanism:
            report_lines.append(
                "- 실패 메커니즘: "
                + compact_text(
                    mechanism[
                        "description"
                    ]
                )
            )

        else:
            report_lines.append(
                "- 실패 메커니즘: "
                "현재 근거만으로 확인되지 않음"
            )

        if causes:
            report_lines.append(
                "- 원인 후보: "
                + compact_text(
                    causes[0][
                        "description"
                    ]
                )
            )

        else:
            report_lines.append(
                "- 원인 후보: "
                "현재 근거만으로 확인되지 않음"
            )

        report_lines.extend([
            "",
            "추가 확인",
        ])

        # 상세 후보 전체는 Trace에 보존하고
        # 운영자에게는 우선순위가 가장 높은 1개만 표시한다.
        if checks:
            check = checks[0]

            report_lines.append(
                "- "
                + compact_text(
                    check[
                        "purpose"
                    ],
                    160
                )
            )

            report_lines.append(
                "  확인 대상: "
                + compact_text(
                    check[
                        "data_source"
                    ],
                    120
                )
            )

        else:
            report_lines.append(
                "- 추가 확인 제안 없음"
            )

        report_lines.extend([
            "",
            "조치 제안",
        ])

        # 상세 복구 후보 전체는 Trace에 보존하고
        # 운영자에게는 우선순위가 가장 높은 1개만 표시한다.
        if remediation:
            action = remediation[0]

            report_lines.append(
                "- "
                + compact_text(
                    action[
                        "action"
                    ],
                    160
                )
            )

            report_lines.append(
                "  이유: "
                + compact_text(
                    action[
                        "rationale"
                    ],
                    180
                )
            )

            report_lines.append(
                "  주의: "
                + compact_text(
                    action[
                        "caution"
                    ],
                    180
                )
            )

        else:
            report_lines.append(
                "- 복구 조치 후보 없음"
            )

    analysis = (
        "\n".join(
            report_lines
        )
        + "\n"
    )

    return (
        analysis,
        trace_entries
    )


def save_llm_trace(
    trace_entries,
    diagnostic_file,
    anomaly_file,
    log_dir
):
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output = os.path.join(
        log_dir,
        f"llm_trace_{timestamp}.json"
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            {
                "diagnostic_file":
                    diagnostic_file,

                "anomaly_file":
                    anomaly_file,

                "findings":
                    trace_entries,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    return output


def save_analysis(
    analysis,
    log_dir
):
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output = os.path.join(
        log_dir,
        f"analysis_{timestamp}.txt"
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(
            analysis
        )

    return output