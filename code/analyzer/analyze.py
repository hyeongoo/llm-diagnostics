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


# LLM과 Python이 공통으로 사용하는
# 진단 데이터 소스 식별자
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


# 현재 상세 수집 단계에서 이미 확보되는 데이터
COLLECTED_DATA_SOURCES = {
    "service_state",
    "systemctl_show",
    "systemctl_status",
    "service_journal"
}


DATA_SOURCE_LABELS = {
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


# 모니터링 대상 읽기
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


# Finding의 대상 Host 결정
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

    # 현재 단일 Host 환경과의 호환
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


# Rule 결과 화면 출력
def format_finding(finding, configured_targets):
    finding_type = finding.get("type")
    target = resolve_target(
        finding,
        configured_targets
    )

    if finding_type == "service_state_mismatch":
        return (
            f"- [{target}] "
            f"{finding.get('service')}: "
            f"expected={finding.get('expected')}, "
            f"actual={finding.get('actual')}"
        )

    if finding_type == "failed_services_exceeded":
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
            f"expected_max={finding.get('expected_max')}, "
            f"actual={finding.get('actual')} "
            f"({service_list})"
        )

    finding_json = json.dumps(
        finding,
        ensure_ascii=False
    )

    return f"- [{target}] {finding_json}"


# Rule Engine 결과를
# 개별 Service 분석 대상으로 변환
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
                        (
                            "systemctl --failed에 "
                            "포함됨"
                        ),

                    "remediation_policy":
                        "pending"
                })

                target_number += 1

    return analysis_targets


# 이상 Service 상세 데이터 수집
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


# systemctl show 구조화
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
            key, value = (
                stripped.split(
                    "=",
                    1
                )
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


# Python이 직접 확인 가능한
# systemd 관측 사실만 생성
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

    clean_deactivation_recorded = (
        "deactivated successfully"
        in detail_lower
    )

    current_failed_state = (
        active_state == "failed"
        or sub_state == "failed"
    )

    non_success_result_recorded = (
        result not in [
            "unknown",
            "",
            "success"
        ]
    )

    non_zero_exec_status_recorded = (
        exec_main_status
        is not None
        and exec_main_status != 0
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
            clean_deactivation_recorded,

        "current_failed_state":
            current_failed_state,

        "non_success_result_recorded":
            non_success_result_recorded,

        "non_zero_exec_status_recorded":
            non_zero_exec_status_recorded
    }


# 현재 이미 수집된 데이터 정보
def build_collected_data_info():
    return {
        "sources": sorted(
            COLLECTED_DATA_SOURCES
        )
    }


# Ollama Structured Output Schema
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
                    "type": "string"
                }
            },

            "cause_candidates": {
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

                        "description": {
                            "type": "string"
                        }
                    },

                    "required": [
                        "host",
                        "service",
                        "description"
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

                        "purpose": {
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
                        },

                        "method": {
                            "type": "string"
                        }
                    },

                    "required": [
                        "host",
                        "service",
                        "purpose",
                        "data_source",
                        "scope",
                        "scope_detail",
                        "method"
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

                        "basis": {
                            "type": "string"
                        }
                    },

                    "required": [
                        "host",
                        "service",
                        "action",
                        "plan",
                        "basis"
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


# Ollama 호출
def call_ollama(
    prompt,
    response_schema
):
    payload = {
        "model": MODEL,

        "prompt": prompt,

        "stream": False,

        "think": False,

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
                .decode("utf-8")
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


def get_string_list(
    item,
    key
):
    value = item.get(
        key,
        []
    )

    if not isinstance(
        value,
        list
    ):
        return []

    values = []

    for entry in value:
        text = str(
            entry
        ).strip()

        if text:
            values.append(
                text
            )

    return values


def normalize_text(value):
    return " ".join(
        str(value)
        .lower()
        .strip()
        .split()
    )


# 구조화된 원인 후보 검증
def get_cause_candidates(
    item,
    expected_host,
    expected_service
):
    candidates = item.get(
        "cause_candidates",
        []
    )

    if not isinstance(
        candidates,
        list
    ):
        return []

    results = []
    seen = set()

    for candidate in candidates:
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

        description = str(
            candidate.get(
                "description",
                ""
            )
        ).strip()

        # 현재 Finding의 Host와
        # Service만 허용
        if (
            host != expected_host
            or service != expected_service
        ):
            continue

        if not description:
            continue

        key = normalize_text(
            description
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        results.append(
            description
        )

    return results


# 구조화된 추가 확인 항목 검증
def get_checks(
    item,
    expected_host,
    expected_service
):
    checks = item.get(
        "checks",
        []
    )

    if not isinstance(
        checks,
        list
    ):
        return []

    valid_checks = []
    seen = set()

    for check in checks:
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

        purpose = str(
            check.get(
                "purpose",
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

        method = str(
            check.get(
                "method",
                ""
            )
        ).strip()

        # 현재 분석 대상만 허용
        if (
            host != expected_host
            or service != expected_service
        ):
            continue

        if (
            not purpose
            or not data_source
            or not scope
            or not method
        ):
            continue

        if (
            data_source
            not in DATA_SOURCE_CATALOG
        ):
            continue

        # 이미 확보한 데이터를
        # 같은 범위에서 다시 보는 것은 제거
        if scope == "existing":
            continue

        source_already_collected = (
            data_source
            in COLLECTED_DATA_SOURCES
        )

        # 이미 수집한 데이터 소스는
        # 새로운 소스(new)가 될 수 없음
        if (
            source_already_collected
            and scope == "new"
        ):
            continue

        # 이미 수집한 데이터 소스라면
        # 추가 범위 조회(expanded)는 가능
        if (
            source_already_collected
            and scope == "expanded"
        ):
            if not scope_detail:
                continue

        # 아직 수집하지 않은 데이터는
        # expanded가 아니라 new여야 함
        if (
            not source_already_collected
            and scope == "expanded"
        ):
            continue

        # 새로운 데이터 소스라면
        # 무엇을 추가 확인할지 설명 필요
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
                purpose
            ),
            data_source,
            scope,
            normalize_text(
                scope_detail
            ),
            normalize_text(
                method
            )
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        valid_checks.append({
            "purpose":
                purpose,

            "data_source":
                data_source,

            "scope":
                scope,

            "scope_detail":
                scope_detail,

            "method":
                method
        })

    return valid_checks


# 복구 후보에 Policy 상태 부여
def evaluate_remediation_candidates(
    item,
    expected_host,
    expected_service,
    remediation_policy
):
    candidates = item.get(
        "remediation_candidates",
        []
    )

    if not isinstance(
        candidates,
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

    policy_reasons = {
        "allowed":
            "정책의 복구 허용 조건이 충족됨",

        "pending":
            "복구 허용 조건이 아직 검증되지 않음",

        "blocked":
            "정책에 의해 복구 조치가 차단됨"
    }

    evaluated = []
    seen = set()

    for candidate in candidates:
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

        basis = str(
            candidate.get(
                "basis",
                ""
            )
        ).strip()

        # Host와 Service를
        # 현재 Finding에 고정
        if (
            host != expected_host
            or service != expected_service
        ):
            continue

        if (
            action
            not in REMEDIATION_ACTION_LABELS
        ):
            continue

        if (
            not plan
            or not basis
        ):
            continue

        key = (
            action,
            normalize_text(
                plan
            ),
            normalize_text(
                basis
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

            "plan":
                plan,

            "basis":
                basis,

            "status":
                remediation_policy,

            "policy_reason":
                policy_reasons[
                    remediation_policy
                ]
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
    anomaly_result.get("status")
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


# Finding별 상세 수집 + LLM 분석
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


    # target / subject 같은 모호한 이름 대신
    # Host와 Service를 명시적으로 분리
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

분석 대상에는 host와 service가 명확하게 구분되어 있습니다.

host:
서비스가 실행되는 서버 또는 SSH 대상입니다.

service:
현재 장애 분석 대상인 systemd 서비스입니다.

host를 service로 해석하면 안 됩니다.
host에 대해 서비스 시작, 재시작, 설정 변경 등의
복구 조치를 제안하면 안 됩니다.

모든 원인 후보, 추가 확인, 복구 후보의 대상은
반드시 현재 service여야 합니다.

분석 대상:

{target_json}

confirmed_fact는 Rule Engine이 이미 확인한 현재 상태입니다.

interpreted_facts는 수집된 systemd 데이터를
Python 코드가 규칙에 따라 정리한 관측 사실입니다.

interpreted_facts에 없는 사실을
임의로 추가하거나 단정하지 마세요.

특정 사람, 프로세스, 자동화 도구 또는 systemd가
서비스 중지를 요청했다는 직접적인 근거가 없다면
종료 요청 주체를 특정하지 마세요.

clean_deactivation_recorded가 true이면
수집된 로그에 정상적인 deactivation 기록이
존재한다는 의미입니다.

이 사실만으로 누가 또는 무엇이
중지를 요청했는지는 판단할 수 없습니다.

current_failed_state,
non_success_result_recorded,
non_zero_exec_status_recorded가 false라는 것은
현재 수집된 해당 필드에서 그 신호가
확인되지 않았다는 의미입니다.

이 값만으로 시스템 전체에 오류가 없었다고
단정하지 마세요.


already_collected_data.sources에 포함된 ID는
현재 분석 입력에서 이미 확보한 데이터 소스입니다.

checks의 data_source는
data_source_catalog에 존재하는 ID만 사용하세요.

checks의 scope 기준:

existing
- 이미 수집된 데이터 소스를
  같은 범위에서 다시 확인하는 경우

expanded
- 이미 수집된 데이터 소스를 사용하지만
  추가 시간 범위, 추가 로그 범위 등
  기존에 없던 범위를 조회하는 경우

new
- 아직 수집되지 않은 새로운 데이터 소스를
  확인하는 경우

already_collected_data.sources에 있는 데이터 소스를
new로 분류하면 안 됩니다.

이미 확보한 데이터를 같은 범위에서
다시 확인하는 existing 항목은
checks에 포함하지 마세요.

expanded를 사용하는 경우에는
scope_detail에 어떤 추가 범위를
확인하는지 구체적으로 작성하세요.

new를 사용하는 경우에는
scope_detail에 새롭게 어떤 정보를
확인하려는지 작성하세요.

checks에는 실제 원인을 좁히기 위해
새로운 정보를 얻을 수 있는
read-only 조사만 작성하세요.


cause_candidates:
- 현재 service의 장애 원인 후보만 작성하세요.
- host를 service처럼 표현하지 마세요.
- confirmed_fact 자체를 단순 반복하지 마세요.
- 실제 근거를 기반으로 작성하세요.
- 가능성을 사실처럼 단정하지 마세요.
- 원인을 특정할 수 없다면 확인 필요라고 작성하세요.


remediation_candidates:
- 실제 시스템 상태를 변경하는 복구 후보입니다.
- 대상 service는 현재 분석 대상 service만 가능합니다.
- host 자체에 대한 서비스 조치를 만들지 마세요.
- 근거가 있는 복구 후보만 작성하세요.
- 억지로 복구 후보를 만들 필요는 없습니다.

action은 다음 의미입니다.

start_service:
서비스 시작

restart_service:
서비스 재시작

reload_service:
서비스 설정 재로드

change_configuration:
서비스 설정 변경

rollback_configuration:
서비스 설정 롤백

failover_service:
서비스 Failover

other:
위 범주에 없는 복구 조치

plan에는 실제 고려할 복구 방법을 작성하세요.

basis에는 왜 해당 복구 조치를 고려할 수 있는지
현재 제공된 근거를 작성하세요.

복구 조치의 허용 여부는 LLM이 결정하지 않습니다.

Python Policy가 별도로 판단하므로
근거가 있는 복구 후보라면
허용 여부를 추측하지 말고 반환하세요.


evidence:
- 실제 제공된 데이터에서 확인되는 근거만 작성하세요.
- 존재하지 않는 로그나 사실을 만들어내지 마세요.

과거 로그와 현재 상태를 구분하세요.

다른 서버나 다른 서비스를
현재 문제의 원인으로 임의로 연결하지 마세요.


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


    evidence = get_string_list(
        item,
        "evidence"
    )


    causes = (
        get_cause_candidates(
            item,
            target_host,
            service
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
            )
        )
    )


    label = (
        f"{target_host} / "
        f"{service}"
    )


    evidence_lines.append(
        f"- [{label}]"
    )

    if evidence:
        evidence_lines.extend(
            f"  - {value}"
            for value in evidence
        )

    else:
        evidence_lines.append(
            "  - 추가 근거 없음"
        )


    cause_lines.append(
        f"- [{label}]"
    )

    if causes:
        cause_lines.extend(
            f"  - {value}"
            for value in causes
        )

    else:
        cause_lines.append(
            "  - 원인 후보 확인 필요"
        )


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
                "  - 목적: "
                f"{check['purpose']}"
            )

            check_lines.append(
                "    데이터: "
                f"{source_label} "
                f"({check['scope']})"
            )

            if check[
                "scope_detail"
            ]:
                check_lines.append(
                    "    범위: "
                    f"{check['scope_detail']}"
                )

            check_lines.append(
                "    방법: "
                f"{check['method']}"
            )

    else:
        check_lines.append(
            "  - 유효한 추가 확인 "
            "항목 없음"
        )


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
                "    유형: "
                f"{candidate['action_label']}"
            )

            remediation_lines.append(
                "    제안: "
                f"{candidate['plan']}"
            )

            remediation_lines.append(
                "    근거: "
                f"{candidate['basis']}"
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