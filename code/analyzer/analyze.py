#!/usr/bin/env python3

import glob
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime

BASE_DIR = os.path.expanduser("~/aiops-openstack")
LOG_DIR = os.path.join(BASE_DIR, "logs")
TARGETS_FILE = os.path.join(BASE_DIR, "config", "targets.txt")
SERVICE_DETAIL_COLLECTOR = os.path.join(
    BASE_DIR,
    "collector",
    "collect_service_detail.sh"
)

OLLAMA_URL = "http://192.168.214.1:11434/api/generate"
MODEL = "qwen3:1.7b"


DATA_SOURCE_LABELS = {
    "rule_finding": "Rule Engine 탐지 결과",
    "systemctl_show": "systemctl show",
    "systemctl_status": "systemctl status",
    "service_journal": "서비스 journal",
}


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


def extract_section_lines(
    detail_data,
    section_name
):
    header = (
        f"===== {section_name} ====="
    )

    result = []
    in_section = False

    for line in detail_data.splitlines():
        stripped = line.strip()

        if stripped == header:
            in_section = True
            continue

        if (
            in_section
            and stripped.startswith(
                "====="
            )
            and stripped.endswith(
                "====="
            )
        ):
            break

        if (
            in_section
            and stripped
        ):
            result.append(
                stripped
            )

    return result


def build_observation_catalog(
    confirmed_fact,
    detail_data
):
    observations = []

    def add(
        source,
        content
    ):
        text = str(
            content
        ).strip()

        if text:
            observations.append({
                "observation_id":
                    f"O{len(observations) + 1}",

                "source":
                    source,

                "content":
                    text,
            })

    add(
        "rule_finding",
        confirmed_fact
    )

    for line in extract_section_lines(
        detail_data,
        "SYSTEMD PROPERTIES"
    ):
        add(
            "systemctl_show",
            line
        )

    for line in extract_section_lines(
        detail_data,
        "SYSTEMCTL STATUS"
    ):
        add(
            "systemctl_status",
            line
        )

    for line in extract_section_lines(
        detail_data,
        "SERVICE JOURNAL"
    ):
        add(
            "service_journal",
            line
        )

    return observations


def build_observation_map(
    observations
):
    return {
        item["observation_id"]:
            item
        for item in observations
    }


def build_response_schema(
    finding_id,
    observation_ids
):
    ref = {
        "type": "string",
        "enum": observation_ids
    }

    return {
        "type": "object",

        "properties": {
            "finding_id": {
                "type": "string",
                "enum": [
                    finding_id
                ]
            },

            "selected_observations": {
                "type": "array",
                "items": ref
            },

            "failure_mechanism": {
                "type": "object",

                "properties": {
                    "identified": {
                        "type": "boolean"
                    },

                    "description": {
                        "type": "string"
                    },

                    "observation_refs": {
                        "type": "array",
                        "items": ref
                    },
                },

                "required": [
                    "identified",
                    "description",
                    "observation_refs"
                ],

                "additionalProperties":
                    False,
            },

            "cause_candidates": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "description": {
                            "type": "string"
                        },

                        "observation_refs": {
                            "type": "array",
                            "items": ref
                        },
                    },

                    "required": [
                        "description",
                        "observation_refs"
                    ],

                    "additionalProperties":
                        False,
                },
            },

            "checks": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "purpose": {
                            "type": "string"
                        },

                        "data_source": {
                            "type": "string"
                        },

                        "scope_detail": {
                            "type": "string"
                        },

                        "observation_refs": {
                            "type": "array",
                            "items": ref
                        },
                    },

                    "required": [
                        "purpose",
                        "data_source",
                        "scope_detail",
                        "observation_refs"
                    ],

                    "additionalProperties":
                        False,
                },
            },

            "remediation_candidates": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "action": {
                            "type": "string"
                        },

                        "rationale": {
                            "type": "string"
                        },

                        "caution": {
                            "type": "string"
                        },

                        "observation_refs": {
                            "type": "array",
                            "items": ref
                        },
                    },

                    "required": [
                        "action",
                        "rationale",
                        "caution",
                        "observation_refs"
                    ],

                    "additionalProperties":
                        False,
                },
            },
        },

        "required": [
            "finding_id",
            "selected_observations",
            "failure_mechanism",
            "cause_candidates",
            "checks",
            "remediation_candidates",
        ],

        "additionalProperties":
            False,
    }


def build_prompt(
    analysis_input
):
    input_json = json.dumps(
        analysis_input,
        ensure_ascii=False,
        indent=2
    )

    return f"""
당신은 Linux/systemd 서비스 장애를 분석하는 진단 보조 AI입니다.
아래 하나의 Host/Service 이상 항목만 분석하세요.

{input_json}

규칙:
- observations만 현재 시스템에서 직접 관측된 사실입니다.
- 존재하지 않는 사실이나 Observation을 만들지 마세요.
- 일반적인 Linux/systemd 지식은 해석에 사용할 수 있지만, 관측된 사실과 추론을 구분하고 확인되지 않은 내용을 확정적으로 표현하지 마세요.
- 실패 메커니즘, 원인 후보, 추가 확인, 복구 후보는 관련 Observation ID를 연결하세요.

- 명령어, 상태, 종료 코드, 설정값이 관측되었다는 이유만으로 설정 오류나 사용자 실수라고 단정하지 마세요.
- failed/inactive, LoadState, UnitFileState 같은 상태나 메타데이터를 근거 없이 장애 원인으로 해석하지 마세요.
- 원인 후보는 Observation과 기술적 근거를 바탕으로 합리적으로 추론할 수 있는 경우에만 제안하고, 확인되지 않은 내용은 가능성으로 표현하세요.
- 근거가 부족하면 cause_candidates를 빈 배열로 반환하세요.

- checks.data_source에는 Observation ID가 아니라 실제로 추가 확인할 로그, 설정, 명령, 시스템 정보 또는 외부 데이터 소스를 작성하세요.
- Python에 미리 정의되지 않은 새로운 데이터 소스도 필요한 경우 자유롭게 제안할 수 있습니다.
- 이미 observations에 답이 있는 내용을 단순히 다시 확인하지 마세요. 같은 데이터 소스를 다시 확인해야 한다면 기존 데이터보다 무엇을 추가로 확인할지 명확히 작성하세요.

- remediation_candidates.action은 Python에 미리 정의된 목록에 맞출 필요가 없습니다.
- 복구 조치는 현재 확인된 사실을 기반으로 제안하고, 확인되지 않은 원인을 전제로 설정 변경이나 재시작을 확정적으로 제안하지 마세요.
- 추가 확인 결과에 따라 가능한 조치라면 조건부로 표현하고, 필요한 확인 사항과 위험 또는 재실패 가능성을 rationale 또는 caution에 작성하세요.
- 복구 조치는 제안일 뿐 실행되지 않습니다.

- selected_observations에는 장애 상태와 실패 과정을 설명하는 데 직접적으로 중요한 근거만 선택하세요.
- 같은 사실을 반복하는 status와 journal 로그는 모두 선택할 필요가 없으며, 장애 판단에 직접 필요하지 않은 부가 정보는 제외하세요.

- 모든 설명은 가능하면 한국어로 작성하세요.

failure_mechanism은 관측 데이터로 설명 가능한 직접적인 실패 과정입니다.
cause_candidates는 왜 그 실패가 발생했는지에 대한 가능한 원인입니다.
둘을 억지로 채울 필요는 없습니다.
"""


def call_ollama(
    prompt,
    response_schema
):
    payload = {
        "model":
            MODEL,

        "prompt":
            prompt,

        "stream":
            False,

        "think":
            False,

        "format":
            response_schema,

        "options": {
            "temperature": 0,
            "seed": 42
        },
    }

    request = urllib.request.Request(
        OLLAMA_URL,

        data=json.dumps(
            payload
        ).encode(
            "utf-8"
        ),

        headers={
            "Content-Type":
                "application/json"
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=300
        ) as response:

            result = json.loads(
                response.read()
                .decode(
                    "utf-8"
                )
            )

    except urllib.error.HTTPError as e:
        print(
            "Ollama HTTP error: "
            f"{e.code} {e.reason}"
        )
        sys.exit(1)

    except urllib.error.URLError as e:
        print(
            "Ollama request failed: "
            f"{e}"
        )
        sys.exit(1)

    except json.JSONDecodeError:
        print(
            "Invalid response from "
            "Ollama API."
        )
        sys.exit(1)

    raw = result.get(
        "response"
    )

    if not raw:
        print(
            "Empty response from LLM."
        )
        sys.exit(1)

    try:
        return json.loads(
            raw
        )

    except json.JSONDecodeError:
        print(
            "Invalid structured response "
            "from LLM."
        )
        sys.exit(1)


def valid_refs(
    value,
    observation_map
):
    if not isinstance(
        value,
        list
    ):
        return []

    refs = []

    for item in value:
        ref = str(
            item
        ).strip()

        if (
            ref in observation_map
            and ref not in refs
        ):
            refs.append(
                ref
            )

    return refs


def validate_response(
    raw,
    finding_id,
    observation_map
):
    """
    Python은 의미를 판단하지 않고
    구조와 Observation 참조만 확인한다.
    """

    if (
        raw.get(
            "finding_id"
        )
        != finding_id
    ):
        print(
            "Unexpected finding_id "
            "from LLM: "
            f"{raw.get('finding_id')}"
        )
        sys.exit(1)

    result = {
        "selected_observations":
            valid_refs(
                raw.get(
                    "selected_observations",
                    []
                ),
                observation_map
            ),

        "failure_mechanism":
            None,

        "cause_candidates":
            [],

        "checks":
            [],

        "remediation_candidates":
            [],
    }

    mechanism = raw.get(
        "failure_mechanism",
        {}
    )

    if (
        isinstance(
            mechanism,
            dict
        )
        and mechanism.get(
            "identified"
        ) is True
    ):
        description = str(
            mechanism.get(
                "description",
                ""
            )
        ).strip()

        refs = valid_refs(
            mechanism.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            description
            and refs
        ):
            result[
                "failure_mechanism"
            ] = {
                "description":
                    description,

                "observation_refs":
                    refs,
            }

    for item in raw.get(
        "cause_candidates",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        description = str(
            item.get(
                "description",
                ""
            )
        ).strip()

        refs = valid_refs(
            item.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            description
            and refs
        ):
            result[
                "cause_candidates"
            ].append({
                "description":
                    description,

                "observation_refs":
                    refs,
            })

    for item in raw.get(
        "checks",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        purpose = str(
            item.get(
                "purpose",
                ""
            )
        ).strip()

        data_source = str(
            item.get(
                "data_source",
                ""
            )
        ).strip()

        scope_detail = str(
            item.get(
                "scope_detail",
                ""
            )
        ).strip()

        refs = valid_refs(
            item.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            purpose
            and data_source
            and scope_detail
            and refs
        ):
            result[
                "checks"
            ].append({
                "purpose":
                    purpose,

                "data_source":
                    data_source,

                "scope_detail":
                    scope_detail,

                "observation_refs":
                    refs,
            })

    for item in raw.get(
        "remediation_candidates",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        action = str(
            item.get(
                "action",
                ""
            )
        ).strip()

        rationale = str(
            item.get(
                "rationale",
                ""
            )
        ).strip()

        caution = str(
            item.get(
                "caution",
                ""
            )
        ).strip()

        refs = valid_refs(
            item.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            action
            and rationale
            and caution
            and refs
        ):
            result[
                "remediation_candidates"
            ].append({
                "action":
                    action,

                "rationale":
                    rationale,

                "caution":
                    caution,

                "observation_refs":
                    refs,
            })

    return result


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


def save_llm_trace(
    trace_entries,
    diagnostic_file,
    anomaly_file
):
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output = os.path.join(
        LOG_DIR,
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

        # 운영자 화면에는 최대 3개의 핵심 근거만 표시한다.
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

    trace_output = (
        save_llm_trace(
            trace_entries,
            latest_log,
            latest_anomaly
        )
    )

    analysis = (
        "\n".join(
            report_lines
        )
        + "\n"
    )

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S"
        )
    )

    output = os.path.join(
        LOG_DIR,
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