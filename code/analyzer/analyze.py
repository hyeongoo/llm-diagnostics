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
TARGETS_FILE = os.path.join(
    BASE_DIR,
    "config",
    "targets.txt"
)

SERVICE_DETAIL_COLLECTOR = os.path.join(
    BASE_DIR,
    "collector",
    "collect_service_detail.sh"
)

OLLAMA_URL = "http://192.168.214.1:11434/api/generate"
MODEL = "qwen3:1.7b"


# LLM과 Python이 공통으로 사용하는 진단 데이터 소스
DATA_SOURCE_CATALOG = [
    "service_state",
    "systemctl_show",
    "systemctl_status",
    "service_journal",
    "unit_configuration",
    "audit_log",
    "application_log",
    "dependency_state",
    "kernel_log",
    "process_state",
    "network_state"
]


# 근거에는 Rule Engine 결과도 사용할 수 있음
EVIDENCE_SOURCE_CATALOG = [
    "rule_finding",
    *DATA_SOURCE_CATALOG
]


# 현재 상세 수집 단계에서 이미 확보되는 데이터
COLLECTED_DATA_SOURCES = {
    "service_state",
    "systemctl_show",
    "systemctl_status",
    "service_journal"
}


DATA_SOURCE_LABELS = {
    "rule_finding": "Rule Engine 탐지 결과",
    "service_state": "서비스 상태",
    "systemctl_show": "systemctl show",
    "systemctl_status": "systemctl status",
    "service_journal": "서비스 journal",
    "unit_configuration": "systemd Unit 설정",
    "audit_log": "Audit 로그",
    "application_log": "애플리케이션 로그",
    "dependency_state": "의존 서비스 상태",
    "kernel_log": "커널 로그",
    "process_state": "프로세스 상태",
    "network_state": "네트워크 상태"
}


REMEDIATION_ACTION_LABELS = {
    "start_service": "서비스 시작",
    "restart_service": "서비스 재시작",
    "reload_service": "서비스 설정 재로드",
    "change_configuration": "설정 변경",
    "rollback_configuration": "설정 롤백",
    "failover_service": "서비스 Failover",
    "other": "기타 복구 조치"
}


# 복구와 원인 교정을 구분
REMEDIATION_ACTION_CATEGORIES = {
    "start_service": "recovery",
    "restart_service": "recovery",
    "reload_service": "recovery",
    "failover_service": "recovery",
    "change_configuration": "corrective",
    "rollback_configuration": "corrective",
    "other": "other"
}


REMEDIATION_CATEGORY_LABELS = {
    "recovery": "서비스 복구",
    "corrective": "원인 교정",
    "other": "기타"
}


def load_targets():
    if not os.path.exists(TARGETS_FILE):
        print(
            f"Targets file not found: "
            f"{TARGETS_FILE}"
        )
        sys.exit(1)

    targets = []

    with open(
        TARGETS_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        for line in f:
            target = line.strip()

            if (
                not target
                or target.startswith("#")
            ):
                continue

            targets.append(target)

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
    finding_target = finding.get(
        "target"
    )

    if finding_target:
        if (
            finding_target
            not in configured_targets
        ):
            print(
                "Finding references an "
                "unknown target: "
                f"{finding_target}"
            )
            sys.exit(1)

        return finding_target

    if len(configured_targets) == 1:
        return configured_targets[0]

    print(
        "Unable to determine target host "
        "for anomaly finding. "
        "Multiple targets are configured, "
        "but the finding does not contain "
        "target information."
    )
    sys.exit(1)


def format_finding(
    finding,
    configured_targets
):
    finding_type = finding.get(
        "type"
    )

    target = resolve_target(
        finding,
        configured_targets
    )

    if (
        finding_type
        == "service_state_mismatch"
    ):
        return (
            f"- [{target}] "
            f"{finding.get('service')}: "
            f"expected="
            f"{finding.get('expected')}, "
            f"actual="
            f"{finding.get('actual')}"
        )

    if (
        finding_type
        == "failed_services_exceeded"
    ):
        services = finding.get(
            "services",
            []
        )

        service_list = (
            ", ".join(services)
            if services
            else "확인 필요"
        )

        return (
            f"- [{target}] "
            f"Failed Services: "
            f"expected_max="
            f"{finding.get('expected_max')}, "
            f"actual="
            f"{finding.get('actual')} "
            f"({service_list})"
        )

    finding_json = json.dumps(
        finding,
        ensure_ascii=False
    )

    return (
        f"- [{target}] "
        f"{finding_json}"
    )


def build_analysis_targets(
    findings,
    configured_targets
):
    analysis_targets = []
    target_number = 1

    for finding in findings:
        finding_type = finding.get(
            "type"
        )

        target_host = resolve_target(
            finding,
            configured_targets
        )

        if (
            finding_type
            == "service_state_mismatch"
        ):
            service = finding.get(
                "service"
            )

            if not service:
                continue

            analysis_targets.append({
                "finding_id":
                    f"F{target_number}",

                "type":
                    "service_state_mismatch",

                "host":
                    target_host,

                "service":
                    service,

                "confirmed_fact": (
                    f"expected="
                    f"{finding.get('expected')}, "
                    f"actual="
                    f"{finding.get('actual')}"
                ),

                "remediation_policy":
                    "pending"
            })

            target_number += 1

        elif (
            finding_type
            == "failed_services_exceeded"
        ):
            for service in finding.get(
                "services",
                []
            ):
                analysis_targets.append({
                    "finding_id":
                        f"F{target_number}",

                    "type":
                        "failed_service",

                    "host":
                        target_host,

                    "service":
                        service,

                    "confirmed_fact":
                        "systemctl --failed에 포함됨",

                    "remediation_policy":
                        "pending"
                })

                target_number += 1

    return analysis_targets


def collect_service_detail(
    target_host,
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
                target_host,
                service
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

    except subprocess.TimeoutExpired:
        print(
            "Service detail collection "
            "timed out: "
            f"{target_host} / "
            f"{service}"
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
            f"{target_host} / "
            f"{service}"
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

    if not detail_path:
        print(
            "Service detail output path "
            "not found: "
            f"{service}"
        )
        sys.exit(1)

    if not os.path.exists(
        detail_path
    ):
        print(
            "Service detail log "
            "not found: "
            f"{detail_path}"
        )
        sys.exit(1)

    return detail_path


def parse_systemd_properties(
    detail_data
):
    properties = {}
    in_properties = False

    for line in detail_data.splitlines():
        stripped = line.strip()

        if (
            stripped
            == "===== SYSTEMD PROPERTIES ====="
        ):
            in_properties = True
            continue

        if (
            in_properties
            and stripped.startswith(
                "====="
            )
        ):
            break

        if (
            in_properties
            and "=" in stripped
        ):
            key, value = stripped.split(
                "=",
                1
            )

            properties[
                key.strip()
            ] = value.strip()

    return properties


def parse_int(value):
    try:
        return int(value)

    except (
        TypeError,
        ValueError
    ):
        return None


def build_interpreted_facts(
    properties,
    detail_data
):
    active_state = (
        properties.get(
            "ActiveState"
        )
        or "unknown"
    )

    sub_state = (
        properties.get(
            "SubState"
        )
        or "unknown"
    )

    result = (
        properties.get(
            "Result"
        )
        or "unknown"
    )

    exec_main_status = parse_int(
        properties.get(
            "ExecMainStatus"
        )
    )

    unit_file_state = (
        properties.get(
            "UnitFileState"
        )
        or "unknown"
    )

    detail_lower = (
        detail_data.lower()
    )

    return {
        "current_active_state":
            active_state,

        "current_sub_state":
            sub_state,

        "unit_file_state":
            unit_file_state,

        "systemd_result":
            result,

        "exec_main_status":
            exec_main_status,

        "clean_deactivation_recorded":
            (
                "deactivated successfully"
                in detail_lower
            ),

        "current_failed_state":
            (
                active_state == "failed"
                or sub_state == "failed"
            ),

        "non_success_result_recorded":
            (
                result not in [
                    "unknown",
                    "",
                    "success"
                ]
            ),

        "non_zero_exec_status_recorded":
            (
                exec_main_status
                is not None
                and exec_main_status != 0
            )
    }


def build_collected_data_info():
    return {
        "sources": sorted(
            COLLECTED_DATA_SOURCES
        )
    }


def build_response_schema(
    finding_id,
    host,
    service
):
    return {
        "type": "object",

        "properties": {
            "finding_id": {
                "type": "string",
                "enum": [
                    finding_id
                ]
            },

            "evidence": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "evidence_id": {
                            "type": "string"
                        },

                        "source": {
                            "type": "string",
                            "enum":
                                EVIDENCE_SOURCE_CATALOG
                        },

                        "fact": {
                            "type": "string"
                        }
                    },

                    "required": [
                        "evidence_id",
                        "source",
                        "fact"
                    ],

                    "additionalProperties":
                        False
                }
            },

            "cause_candidates": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "cause_id": {
                            "type": "string"
                        },

                        "host": {
                            "type": "string",
                            "enum": [
                                host
                            ]
                        },

                        "service": {
                            "type": "string",
                            "enum": [
                                service
                            ]
                        },

                        "description": {
                            "type": "string"
                        },

                        "evidence_refs": {
                            "type": "array",

                            "items": {
                                "type": "string"
                            }
                        }
                    },

                    "required": [
                        "cause_id",
                        "host",
                        "service",
                        "description",
                        "evidence_refs"
                    ],

                    "additionalProperties":
                        False
                }
            },

            "checks": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "host": {
                            "type": "string",
                            "enum": [
                                host
                            ]
                        },

                        "service": {
                            "type": "string",
                            "enum": [
                                service
                            ]
                        },

                        "question": {
                            "type": "string"
                        },

                        "data_source": {
                            "type": "string",
                            "enum":
                                DATA_SOURCE_CATALOG
                        },

                        "scope": {
                            "type": "string",

                            "enum": [
                                "existing",
                                "expanded",
                                "new"
                            ]
                        },

                        "scope_detail": {
                            "type": "string"
                        }
                    },

                    "required": [
                        "host",
                        "service",
                        "question",
                        "data_source",
                        "scope",
                        "scope_detail"
                    ],

                    "additionalProperties":
                        False
                }
            },

            "remediation_candidates": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "host": {
                            "type": "string",
                            "enum": [
                                host
                            ]
                        },

                        "service": {
                            "type": "string",
                            "enum": [
                                service
                            ]
                        },

                        "action": {
                            "type": "string",
                            "enum": list(
                                REMEDIATION_ACTION_LABELS
                                .keys()
                            )
                        },

                        "plan": {
                            "type": "string"
                        },

                        "evidence_refs": {
                            "type": "array",

                            "items": {
                                "type": "string"
                            }
                        },

                        "cause_refs": {
                            "type": "array",

                            "items": {
                                "type": "string"
                            }
                        },

                        "prerequisites": {
                            "type": "array",

                            "items": {
                                "type": "string"
                            }
                        }
                    },

                    "required": [
                        "host",
                        "service",
                        "action",
                        "plan",
                        "evidence_refs",
                        "cause_refs",
                        "prerequisites"
                    ],

                    "additionalProperties":
                        False
                }
            }
        },

        "required": [
            "finding_id",
            "evidence",
            "cause_candidates",
            "checks",
            "remediation_candidates"
        ],

        "additionalProperties": False
    }


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
        }
    }

    data = json.dumps(
        payload
    ).encode(
        "utf-8"
    )

    request = urllib.request.Request(
        OLLAMA_URL,

        data=data,

        headers={
            "Content-Type":
                "application/json"
        }
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
            f"{e.code} "
            f"{e.reason}"
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

    raw_analysis = result.get(
        "response"
    )

    if not raw_analysis:
        print(
            "Empty response from LLM."
        )
        sys.exit(1)

    try:
        return json.loads(
            raw_analysis
        )

    except json.JSONDecodeError:
        print(
            "Invalid structured response "
            "from LLM."
        )
        sys.exit(1)


def normalize_text(value):
    return " ".join(
        str(value)
        .lower()
        .strip()
        .split()
    )


def get_string_list(value):
    if not isinstance(
        value,
        list
    ):
        return []

    results = []

    for item in value:
        text = str(
            item
        ).strip()

        if text:
            results.append(
                text
            )

    return results


# LLM이 선택한 근거를 구조적으로 검증
def get_evidence(item):
    raw_evidence = item.get(
        "evidence",
        []
    )

    if not isinstance(
        raw_evidence,
        list
    ):
        return [], {}

    evidence = []
    evidence_map = {}

    for entry in raw_evidence:
        if not isinstance(
            entry,
            dict
        ):
            continue

        evidence_id = str(
            entry.get(
                "evidence_id",
                ""
            )
        ).strip()

        source = str(
            entry.get(
                "source",
                ""
            )
        ).strip()

        fact = str(
            entry.get(
                "fact",
                ""
            )
        ).strip()

        if (
            not evidence_id
            or not fact
        ):
            continue

        if (
            source
            not in EVIDENCE_SOURCE_CATALOG
        ):
            continue

        if (
            evidence_id
            in evidence_map
        ):
            continue

        normalized = {
            "evidence_id":
                evidence_id,

            "source":
                source,

            "fact":
                fact
        }

        evidence.append(
            normalized
        )

        evidence_map[
            evidence_id
        ] = normalized

    return (
        evidence,
        evidence_map
    )


# 원인 후보가 실제 근거를 참조하는지 검증
def get_cause_candidates(
    item,
    expected_host,
    expected_service,
    evidence_map
):
    raw_candidates = item.get(
        "cause_candidates",
        []
    )

    if not isinstance(
        raw_candidates,
        list
    ):
        return [], {}

    candidates = []
    cause_map = {}
    seen_descriptions = set()

    for candidate in raw_candidates:
        if not isinstance(
            candidate,
            dict
        ):
            continue

        cause_id = str(
            candidate.get(
                "cause_id",
                ""
            )
        ).strip()

        host = str(
            candidate.get(
                "host",
                ""
            )
        ).strip()

        service = str(
            candidate.get(
                "service",
                ""
            )
        ).strip()

        description = str(
            candidate.get(
                "description",
                ""
            )
        ).strip()

        evidence_refs = get_string_list(
            candidate.get(
                "evidence_refs",
                []
            )
        )

        valid_evidence_refs = [
            ref
            for ref in evidence_refs
            if ref in evidence_map
        ]

        if (
            host != expected_host
            or service != expected_service
        ):
            continue

        if (
            not cause_id
            or not description
            or not valid_evidence_refs
        ):
            continue

        if cause_id in cause_map:
            continue

        description_key = (
            normalize_text(
                description
            )
        )

        if (
            description_key
            in seen_descriptions
        ):
            continue

        seen_descriptions.add(
            description_key
        )

        normalized = {
            "cause_id":
                cause_id,

            "description":
                description,

            "evidence_refs":
                valid_evidence_refs
        }

        candidates.append(
            normalized
        )

        cause_map[
            cause_id
        ] = normalized

    return (
        candidates,
        cause_map
    )


# 추가 확인 항목 검증
def get_checks(
    item,
    expected_host,
    expected_service
):
    raw_checks = item.get(
        "checks",
        []
    )

    if not isinstance(
        raw_checks,
        list
    ):
        return []

    valid_checks = []
    seen = set()

    for check in raw_checks:
        if not isinstance(
            check,
            dict
        ):
            continue

        host = str(
            check.get(
                "host",
                ""
            )
        ).strip()

        service = str(
            check.get(
                "service",
                ""
            )
        ).strip()

        question = str(
            check.get(
                "question",
                ""
            )
        ).strip()

        data_source = str(
            check.get(
                "data_source",
                ""
            )
        ).strip()

        scope = str(
            check.get(
                "scope",
                ""
            )
        ).strip()

        scope_detail = str(
            check.get(
                "scope_detail",
                ""
            )
        ).strip()

        if (
            host != expected_host
            or service != expected_service
        ):
            continue

        if (
            not question
            or not data_source
            or not scope
        ):
            continue

        if (
            data_source
            not in DATA_SOURCE_CATALOG
        ):
            continue

        # 이미 확보한 데이터를 같은 범위에서
        # 다시 보는 확인은 제거
        if scope == "existing":
            continue

        source_already_collected = (
            data_source
            in COLLECTED_DATA_SOURCES
        )

        # 이미 수집된 Source는
        # 새로운 Source가 될 수 없음
        if (
            source_already_collected
            and scope == "new"
        ):
            continue

        # 기존 Source의 추가 범위는 허용
        if (
            source_already_collected
            and scope == "expanded"
            and not scope_detail
        ):
            continue

        # 아직 수집되지 않은 Source는
        # expanded가 아니라 new
        if (
            not source_already_collected
            and scope == "expanded"
        ):
            continue

        if (
            not source_already_collected
            and scope == "new"
            and not scope_detail
        ):
            continue

        if scope not in [
            "expanded",
            "new"
        ]:
            continue

        key = (
            normalize_text(
                question
            ),
            data_source,
            scope,
            normalize_text(
                scope_detail
            )
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        valid_checks.append({
            "question":
                question,

            "data_source":
                data_source,

            "scope":
                scope,

            "scope_detail":
                scope_detail
        })

    return valid_checks


# 복구 후보를 근거/원인과 연결한 뒤
# Policy 상태 부여
def evaluate_remediation_candidates(
    item,
    expected_host,
    expected_service,
    remediation_policy,
    evidence_map,
    cause_map
):
    raw_candidates = item.get(
        "remediation_candidates",
        []
    )

    if not isinstance(
        raw_candidates,
        list
    ):
        return []

    if remediation_policy not in [
        "allowed",
        "pending",
        "blocked"
    ]:
        remediation_policy = (
            "pending"
        )

    evaluated = []
    seen = set()

    for candidate in raw_candidates:
        if not isinstance(
            candidate,
            dict
        ):
            continue

        host = str(
            candidate.get(
                "host",
                ""
            )
        ).strip()

        service = str(
            candidate.get(
                "service",
                ""
            )
        ).strip()

        action = str(
            candidate.get(
                "action",
                ""
            )
        ).strip()

        plan = str(
            candidate.get(
                "plan",
                ""
            )
        ).strip()

        evidence_refs = get_string_list(
            candidate.get(
                "evidence_refs",
                []
            )
        )

        cause_refs = get_string_list(
            candidate.get(
                "cause_refs",
                []
            )
        )

        prerequisites = get_string_list(
            candidate.get(
                "prerequisites",
                []
            )
        )

        if (
            host != expected_host
            or service != expected_service
        ):
            continue

        if (
            action
            not in REMEDIATION_ACTION_LABELS
            or not plan
        ):
            continue

        valid_evidence_refs = [
            ref
            for ref in evidence_refs
            if ref in evidence_map
        ]

        valid_cause_refs = [
            ref
            for ref in cause_refs
            if ref in cause_map
        ]

        # 아무 근거와도 연결되지 않은
        # 복구 후보는 출력하지 않음
        if (
            not valid_evidence_refs
            and not valid_cause_refs
        ):
            continue

        category = (
            REMEDIATION_ACTION_CATEGORIES[
                action
            ]
        )

        if (
            remediation_policy
            == "allowed"
        ):
            policy_reason = (
                "정책의 복구 허용 조건이 "
                "충족됨"
            )

        elif (
            remediation_policy
            == "blocked"
        ):
            policy_reason = (
                "정책에 의해 복구 조치가 "
                "차단됨"
            )

        elif (
            category == "corrective"
            and not valid_cause_refs
        ):
            policy_reason = (
                "원인과의 연결 및 복구 허용 "
                "조건이 검증되지 않아 보류"
            )

        elif (
            category == "corrective"
        ):
            policy_reason = (
                "원인 교정 조치의 사전조건과 "
                "복구 허용 조건이 아직 "
                "검증되지 않음"
            )

        else:
            policy_reason = (
                "복구 허용 조건이 아직 "
                "검증되지 않음"
            )

        key = (
            action,
            normalize_text(
                plan
            ),
            tuple(
                valid_evidence_refs
            ),
            tuple(
                valid_cause_refs
            )
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        evaluated.append({
            "service":
                service,

            "action":
                action,

            "action_label":
                REMEDIATION_ACTION_LABELS[
                    action
                ],

            "category":
                category,

            "category_label":
                REMEDIATION_CATEGORY_LABELS[
                    category
                ],

            "plan":
                plan,

            "evidence_refs":
                valid_evidence_refs,

            "cause_refs":
                valid_cause_refs,

            "prerequisites":
                prerequisites,

            "status":
                remediation_policy,

            "policy_reason":
                policy_reason
        })

    return evaluated


# -------------------------
# 분석 시작
# -------------------------

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


finding_lines = [
    format_finding(
        finding,
        configured_targets
    )
    for finding in findings
]


analysis_targets = (
    build_analysis_targets(
        findings,
        configured_targets
    )
)


if not analysis_targets:
    print(
        "No analysis target found."
    )
    sys.exit(1)


rule_analysis = (
    "## 1. 상태 요약\n"
    "- 규칙 기반 이상 상태가 탐지됨\n"
    "- 탐지 상태: ANOMALY\n\n"
    "## 2. 이상 징후\n"
    + "\n".join(
        finding_lines
    )
)


llm_results = {}
detail_cache = {}


for target in analysis_targets:
    finding_id = target[
        "finding_id"
    ]

    target_host = target[
        "host"
    ]

    service = target[
        "service"
    ]

    cache_key = (
        target_host,
        service
    )


    if (
        cache_key
        not in detail_cache
    ):
        detail_path = (
            collect_service_detail(
                target_host,
                service
            )
        )

        with open(
            detail_path,
            "r",
            encoding="utf-8"
        ) as f:
            detail_data = (
                f.read()
            )

        detail_cache[
            cache_key
        ] = {
            "path":
                detail_path,

            "data":
                detail_data
        }

    else:
        detail_path = (
            detail_cache[
                cache_key
            ]["path"]
        )

        detail_data = (
            detail_cache[
                cache_key
            ]["data"]
        )


    print(
        "Detail     : "
        f"{target_host} / "
        f"{service} -> "
        f"{detail_path}"
    )


    systemd_properties = (
        parse_systemd_properties(
            detail_data
        )
    )


    interpreted_facts = (
        build_interpreted_facts(
            systemd_properties,
            detail_data
        )
    )


    collected_data = (
        build_collected_data_info()
    )


    analysis_input = {
        "finding_id":
            finding_id,

        "finding_type":
            target["type"],

        "host":
            target_host,

        "service":
            service,

        "confirmed_fact":
            target[
                "confirmed_fact"
            ],

        "systemd_properties":
            systemd_properties,

        "interpreted_facts":
            interpreted_facts,

        "already_collected_data":
            collected_data,

        "data_source_catalog":
            DATA_SOURCE_CATALOG
    }


    target_json = json.dumps(
        analysis_input,
        ensure_ascii=False,
        indent=2
    )


    response_schema = (
        build_response_schema(
            finding_id,
            target_host,
            service
        )
    )


    prompt = f"""
당신은 Linux systemd 서비스 장애 진단을 지원하는 분석기입니다.

아래 하나의 이상 항목만 분석하세요.

host는 서비스가 실행되는 서버 또는 SSH 대상이고,
service는 현재 장애 분석 대상인 systemd 서비스입니다.

host를 service로 해석하면 안 됩니다.

모든 원인 후보, 추가 확인, 복구 후보의 대상은
현재 service여야 합니다.

분석 대상:

{target_json}

confirmed_fact는 Rule Engine이 이미 확인한 현재 상태입니다.

interpreted_facts는 수집된 systemd 데이터를
Python 코드가 정리한 관측 사실입니다.

제공된 데이터에 없는 사실을
임의로 추가하거나 단정하지 마세요.

특정 사람, 프로세스, 자동화 도구 또는 systemd가
서비스 중지를 요청했다는 직접적인 근거가 없다면
종료 요청 주체를 특정하지 마세요.

clean_deactivation_recorded가 true라는 사실만으로
누가 또는 무엇이 중지를 요청했는지는
판단할 수 없습니다.

current_failed_state,
non_success_result_recorded,
non_zero_exec_status_recorded가 false라는 사실만으로
시스템 전체에 오류가 없었다고 단정하지 마세요.


[evidence]

- 실제 제공된 데이터에서 직접 확인되는
  관측 사실만 작성하세요.

- 각 근거에 E1, E2, E3처럼
  고유한 evidence_id를 부여하세요.

- source는 허용된 source ID만 사용하세요.

- 원인 추정이나 복구 제안은
  evidence에 작성하지 마세요.


[cause_candidates]

- 원인 후보에는 C1, C2처럼
  고유한 cause_id를 부여하세요.

- 반드시 하나 이상의 evidence_id를
  evidence_refs로 연결하세요.

- 단순히 failed/inactive 상태를
  다시 표현하는 대신,
  현재 근거가 설명하는 실패 메커니즘 또는
  가능한 원인을 작성하세요.

- 직접적인 근거가 부족하면
  가능성으로 표현하세요.

- 다른 Host나 다른 Service를
  임의로 원인으로 연결하지 마세요.


[checks]

- 이미 수집한 데이터를 같은 범위에서
  다시 보는 항목은 제외하세요.

- question에는 실제로 무엇을 알아내려는지
  구체적인 질문 또는 조사 목적을 작성하세요.

- question에 existing, expanded, new 같은
  scope 이름을 그대로 쓰지 마세요.

- data_source는 data_source_catalog의
  ID만 사용하세요.

- already_collected_data.sources에 있는
  source를 new로 분류하지 마세요.

- expanded는 기존 Source의 시간 범위,
  로그 범위 또는 문맥을 넓혀
  새 정보를 얻는 경우입니다.

- new는 현재 수집되지 않은
  새로운 Source를 확인하는 경우입니다.

- scope_detail에는 실제로 어떤 추가 범위나
  새 정보를 확인할지 구체적으로 작성하세요.

- "read-only", "log_analysis", "expanded"처럼
  추상적인 표현만 작성하지 마세요.


[remediation_candidates]

- 복구 후보는 현재 근거 및 원인 후보와
  연결해서 제안하세요.

- evidence_refs에는 실제 사용한
  evidence_id만 넣으세요.

- cause_refs에는 실제 사용한
  cause_id만 넣으세요.

- prerequisites에는 조치 전에
  확인되어야 할 조건을 작성하세요.

- start/restart/failover처럼 서비스를
  다시 정상 상태로 만드는 조치는
  원인 제거가 아니라
  "서비스 복구 시도"로 표현하세요.

- 근거가 없는 상태에서
  "원인을 제거한다",
  "문제를 해결한다"고 단정하지 마세요.

- 설정 변경이나 설정 롤백은
  설정 또는 원인과의 연결이
  실제 근거로 뒷받침될 때만
  후보로 제안하세요.

- 복구 조치의 허용 여부는
  LLM이 판단하지 않습니다.

- Python Policy가 별도로 판단하므로
  허용 여부를 추측하지 마세요.

- 근거가 부족하다면
  복구 후보를 억지로 만들지 마세요.


과거 로그와 현재 상태를 구분하세요.

가능성을 사실처럼 단정하지 마세요.


SERVICE_DETAIL:

{detail_data}
"""


    structured_analysis = (
        call_ollama(
            prompt,
            response_schema
        )
    )


    if (
        structured_analysis.get(
            "finding_id"
        )
        != finding_id
    ):
        print(
            "Unexpected finding_id "
            "from LLM: "
            f"{finding_id}"
        )
        sys.exit(1)


    llm_results[
        finding_id
    ] = structured_analysis


# -------------------------
# 최종 결과 생성
# -------------------------

evidence_lines = []
cause_lines = []
check_lines = []
remediation_lines = []


status_labels = {
    "allowed": "허용",
    "pending": "보류",
    "blocked": "차단"
}


for target in analysis_targets:
    finding_id = target[
        "finding_id"
    ]

    target_host = target[
        "host"
    ]

    service = target[
        "service"
    ]

    item = llm_results.get(
        finding_id,
        {}
    )

    label = (
        f"{target_host} / "
        f"{service}"
    )


    evidence, evidence_map = (
        get_evidence(
            item
        )
    )


    causes, cause_map = (
        get_cause_candidates(
            item,
            target_host,
            service,
            evidence_map
        )
    )


    checks = get_checks(
        item,
        target_host,
        service
    )


    remediation_candidates = (
        evaluate_remediation_candidates(
            item,
            target_host,
            service,
            target.get(
                "remediation_policy",
                "pending"
            ),
            evidence_map,
            cause_map
        )
    )


    # 근거 출력
    evidence_lines.append(
        f"- [{label}]"
    )

    if evidence:
        for entry in evidence:
            source_label = (
                DATA_SOURCE_LABELS.get(
                    entry["source"],
                    entry["source"]
                )
            )

            evidence_lines.append(
                f"  - "
                f"[{entry['evidence_id']}] "
                f"[{source_label}] "
                f"{entry['fact']}"
            )

    else:
        evidence_lines.append(
            "  - 추가 근거 없음"
        )


    # 원인 후보 출력
    cause_lines.append(
        f"- [{label}]"
    )

    if causes:
        for cause in causes:
            cause_lines.append(
                f"  - "
                f"[{cause['cause_id']}] "
                f"{cause['description']}"
            )

            cause_lines.append(
                "    근거: "
                + ", ".join(
                    cause[
                        "evidence_refs"
                    ]
                )
            )

    else:
        cause_lines.append(
            "  - 원인 후보 확인 필요"
        )


    # 추가 확인 출력
    check_lines.append(
        f"- [{label}]"
    )

    if checks:
        for check in checks:
            source_label = (
                DATA_SOURCE_LABELS.get(
                    check[
                        "data_source"
                    ],
                    check[
                        "data_source"
                    ]
                )
            )

            check_lines.append(
                "  - 확인: "
                f"{check['question']}"
            )

            check_lines.append(
                "    데이터: "
                f"{source_label} "
                f"({check['scope']})"
            )

            check_lines.append(
                "    범위: "
                f"{check['scope_detail']}"
            )

    else:
        check_lines.append(
            "  - 유효한 추가 확인 "
            "항목 없음"
        )


    # 복구 후보 출력
    remediation_lines.append(
        f"- [{label}]"
    )

    if remediation_candidates:
        for candidate in (
            remediation_candidates
        ):
            status = candidate[
                "status"
            ]

            remediation_lines.append(
                "  - 대상: "
                f"{candidate['service']}"
            )

            remediation_lines.append(
                "    분류: "
                f"{candidate['category_label']}"
            )

            remediation_lines.append(
                "    유형: "
                f"{candidate['action_label']}"
            )

            remediation_lines.append(
                "    제안: "
                f"{candidate['plan']}"
            )

            if candidate[
                "evidence_refs"
            ]:
                remediation_lines.append(
                    "    연결 근거: "
                    + ", ".join(
                        candidate[
                            "evidence_refs"
                        ]
                    )
                )

            if candidate[
                "cause_refs"
            ]:
                remediation_lines.append(
                    "    연결 원인: "
                    + ", ".join(
                        candidate[
                            "cause_refs"
                        ]
                    )
                )

            if candidate[
                "prerequisites"
            ]:
                remediation_lines.append(
                    "    사전조건:"
                )

                remediation_lines.extend(
                    f"      - {value}"
                    for value
                    in candidate[
                        "prerequisites"
                    ]
                )

            remediation_lines.append(
                "    상태: "
                f"{status_labels[status]} "
                f"({status})"
            )

            remediation_lines.append(
                "    정책: "
                f"{candidate['policy_reason']}"
            )

    else:
        remediation_lines.append(
            "  - 근거 기반 복구 조치 "
            "후보 없음"
        )


llm_analysis = (
    "## 3. 근거\n"
    + "\n".join(
        evidence_lines
    )
    + "\n\n"
    "## 4. 원인 후보\n"
    + "\n".join(
        cause_lines
    )
    + "\n\n"
    "## 5. 추가 확인 항목\n"
    + "\n".join(
        check_lines
    )
    + "\n\n"
    "## 6. 복구 조치 후보\n"
    + "\n".join(
        remediation_lines
    )
)


analysis = (
    f"{rule_analysis}\n\n"
    f"{llm_analysis}\n"
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
    f"Output     : {output}"
)

print()

print(
    analysis
)