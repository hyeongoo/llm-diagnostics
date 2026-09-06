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


# 모니터링 대상 목록 읽기
def load_targets():
    if not os.path.exists(TARGETS_FILE):
        print(f"Targets file not found: {TARGETS_FILE}")
        sys.exit(1)

    targets = []

    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            target = line.strip()

            if not target or target.startswith("#"):
                continue

            targets.append(target)

    if not targets:
        print("No monitoring target defined.")
        sys.exit(1)

    return targets


# Finding이 어느 서버에서 발생했는지 결정
def resolve_target(finding, configured_targets):
    finding_target = finding.get("target")

    if finding_target:
        if finding_target not in configured_targets:
            print(
                "Finding references an unknown target: "
                f"{finding_target}"
            )
            sys.exit(1)

        return finding_target

    # 현재 단일 서버 환경과의 호환
    if len(configured_targets) == 1:
        return configured_targets[0]

    print(
        "Unable to determine target host for anomaly finding. "
        "Multiple targets are configured, but the finding "
        "does not contain target information."
    )
    sys.exit(1)


# Rule 기반 결과를 화면 출력용 형태로 변환
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
        services = finding.get("services", [])

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

    return (
        f"- [{target}] "
        f"{json.dumps(finding, ensure_ascii=False)}"
    )


# Rule Engine 결과를 LLM 분석 대상으로 변환
def build_analysis_targets(findings, configured_targets):
    analysis_targets = []
    target_number = 1

    for finding in findings:
        finding_type = finding.get("type")

        target_host = resolve_target(
            finding,
            configured_targets
        )

        if finding_type == "service_state_mismatch":
            service = finding.get("service")

            if not service:
                continue

            analysis_targets.append({
                "finding_id": f"F{target_number}",
                "type": "service_state_mismatch",
                "target": target_host,
                "subject": service,
                "confirmed_fact": (
                    f"expected={finding.get('expected')}, "
                    f"actual={finding.get('actual')}"
                ),

                # 현재는 복구 허용 조건을 별도로
                # 검증하지 않았으므로 기본 상태는 pending
                "remediation_policy": "pending"
            })

            target_number += 1

        elif finding_type == "failed_services_exceeded":
            for service in finding.get("services", []):
                analysis_targets.append({
                    "finding_id": f"F{target_number}",
                    "type": "failed_service",
                    "target": target_host,
                    "subject": service,
                    "confirmed_fact": (
                        "systemctl --failed에 포함됨"
                    ),
                    "remediation_policy": "pending"
                })

                target_number += 1

    return analysis_targets


# 이상 서비스 상세 진단 데이터 자동 수집
def collect_service_detail(target_host, service):
    if not os.path.exists(SERVICE_DETAIL_COLLECTOR):
        print(
            "Service detail collector not found: "
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
            "Service detail collection timed out: "
            f"{target_host} / {service}"
        )
        sys.exit(1)

    except OSError as e:
        print(
            "Failed to execute service detail collector: "
            f"{e}"
        )
        sys.exit(1)

    if result.returncode != 0:
        print(
            "Service detail collection failed: "
            f"{target_host} / {service}"
        )

        if result.stderr.strip():
            print(result.stderr.strip())

        sys.exit(1)

    detail_path = None

    for line in result.stdout.splitlines():
        if line.startswith("Collected: "):
            detail_path = (
                line[len("Collected: "):]
                .strip()
            )

    if not detail_path:
        print(
            "Service detail output path not found: "
            f"{service}"
        )
        sys.exit(1)

    if not os.path.exists(detail_path):
        print(
            f"Service detail log not found: {detail_path}"
        )
        sys.exit(1)

    return detail_path


# systemctl show 결과에서 구조화된 값 추출
def parse_systemd_properties(detail_data):
    properties = {}
    in_properties = False

    for line in detail_data.splitlines():
        stripped = line.strip()

        if stripped == "===== SYSTEMD PROPERTIES =====":
            in_properties = True
            continue

        if in_properties and stripped.startswith("====="):
            break

        if in_properties and "=" in stripped:
            key, value = stripped.split("=", 1)

            properties[key.strip()] = value.strip()

    return properties


def parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# 수집된 systemd 데이터에서
# 코드로 직접 확인 가능한 사실만 정리
def build_interpreted_facts(properties, detail_data):
    active_state = (
        properties.get("ActiveState")
        or "unknown"
    )

    sub_state = (
        properties.get("SubState")
        or "unknown"
    )

    result = (
        properties.get("Result")
        or "unknown"
    )

    exec_main_status = parse_int(
        properties.get("ExecMainStatus")
    )

    unit_file_state = (
        properties.get("UnitFileState")
        or "unknown"
    )

    detail_lower = detail_data.lower()

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
        exec_main_status is not None
        and exec_main_status != 0
    )

    return {
        "current_active_state": active_state,
        "current_sub_state": sub_state,
        "unit_file_state": unit_file_state,
        "systemd_result": result,
        "exec_main_status": exec_main_status,
        "clean_deactivation_recorded": (
            clean_deactivation_recorded
        ),
        "current_failed_state": (
            current_failed_state
        ),
        "non_success_result_recorded": (
            non_success_result_recorded
        ),
        "non_zero_exec_status_recorded": (
            non_zero_exec_status_recorded
        )
    }


# 현재 분석 입력으로 이미 확보한 데이터 소스
def build_collected_data_info():
    return {
        "sources": [
            "service_state",
            "systemctl_show",
            "systemctl_status",
            "service_journal"
        ]
    }


# Ollama Structured Output Schema 생성
def build_response_schema(finding_id):
    return {
        "type": "object",
        "properties": {
            "finding_id": {
                "type": "string",
                "enum": [finding_id]
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
                    "type": "string"
                }
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
                        "scope": {
                            "type": "string",
                            "enum": [
                                "existing",
                                "expanded",
                                "new"
                            ]
                        },
                        "method": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "purpose",
                        "data_source",
                        "scope",
                        "method"
                    ],
                    "additionalProperties": False
                }
            },
            "remediation_candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string"
                        },
                        "basis": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "description",
                        "basis"
                    ],
                    "additionalProperties": False
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
def call_ollama(prompt, response_schema):
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "format": response_schema,
        "options": {
            "temperature": 0,
            "seed": 42
        }
    }

    data = json.dumps(
        payload
    ).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=300
        ) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as e:
        print(
            f"Ollama HTTP error: "
            f"{e.code} {e.reason}"
        )
        sys.exit(1)

    except urllib.error.URLError as e:
        print(
            f"Ollama request failed: {e}"
        )
        sys.exit(1)

    except json.JSONDecodeError:
        print(
            "Invalid response from Ollama API."
        )
        sys.exit(1)

    raw_analysis = result.get("response")

    if not raw_analysis:
        print("Empty response from LLM.")
        sys.exit(1)

    try:
        return json.loads(raw_analysis)

    except json.JSONDecodeError:
        print(
            "Invalid structured response from LLM."
        )
        sys.exit(1)


def get_string_list(item, key):
    value = item.get(key, [])

    if not isinstance(value, list):
        return []

    values = []

    for entry in value:
        text = str(entry).strip()

        if text:
            values.append(text)

    return values


# 문자열 비교용 정규화
def normalize_text(value):
    return " ".join(
        str(value)
        .lower()
        .strip()
        .split()
    )


# 조사 항목에 실제 시스템 변경 명령이
# 섞여 들어오는 경우를 막기 위한 일반 안전장치
def looks_like_mutating_action(description):
    text = normalize_text(description)

    mutating_patterns = [
        "재시작",
        "재부팅",
        "서비스 시작",
        "서비스를 시작",
        "서비스 중지",
        "서비스를 중지",
        "설정 변경",
        "설정을 변경",
        "설정 수정",
        "설정을 수정",
        "파일 삭제",
        "restart ",
        "reboot",
        "systemctl restart",
        "systemctl start",
        "systemctl stop",
        "systemctl enable",
        "systemctl disable"
    ]

    return any(
        pattern in text
        for pattern in mutating_patterns
    )


# 구조화된 scope를 기준으로
# 실제 새로운 진단 정보만 남김
def get_checks(item):
    checks = item.get("checks", [])

    if not isinstance(checks, list):
        return []

    valid_checks = []
    seen = set()

    for check in checks:
        if not isinstance(check, dict):
            continue

        purpose = str(
            check.get("purpose", "")
        ).strip()

        data_source = str(
            check.get("data_source", "")
        ).strip()

        scope = str(
            check.get("scope", "")
        ).strip()

        method = str(
            check.get("method", "")
        ).strip()

        if (
            not purpose
            or not data_source
            or not scope
            or not method
        ):
            continue

        # 이미 제공된 데이터를 그대로 다시 보는 항목은 제거
        if scope == "existing":
            continue

        if scope not in [
            "expanded",
            "new"
        ]:
            continue

        # 추가 확인 항목은 read-only 조사여야 함
        if looks_like_mutating_action(method):
            continue

        key = (
            normalize_text(purpose),
            normalize_text(data_source),
            scope,
            normalize_text(method)
        )

        if key in seen:
            continue

        seen.add(key)

        valid_checks.append({
            "purpose": purpose,
            "data_source": data_source,
            "scope": scope,
            "method": method
        })

    return valid_checks


# 복구 조치 후보에 Python Policy 상태 부여
def evaluate_remediation_candidates(
    item,
    remediation_policy
):
    candidates = item.get(
        "remediation_candidates",
        []
    )

    if not isinstance(candidates, list):
        return []

    if remediation_policy not in [
        "allowed",
        "pending",
        "blocked"
    ]:
        remediation_policy = "pending"

    policy_reasons = {
        "allowed": (
            "정책의 복구 허용 조건이 충족됨"
        ),
        "pending": (
            "복구 허용 조건이 아직 검증되지 않음"
        ),
        "blocked": (
            "정책에 의해 복구 조치가 차단됨"
        )
    }

    evaluated = []
    seen = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue

        description = str(
            candidate.get("description", "")
        ).strip()

        basis = str(
            candidate.get("basis", "")
        ).strip()

        if not description or not basis:
            continue

        key = (
            normalize_text(description),
            normalize_text(basis)
        )

        if key in seen:
            continue

        seen.add(key)

        evaluated.append({
            "description": description,
            "basis": basis,
            "status": remediation_policy,
            "policy_reason": (
                policy_reasons[
                    remediation_policy
                ]
            )
        })

    return evaluated


# -------------------------
# 분석 시작
# -------------------------

configured_targets = load_targets()

anomaly_files = glob.glob(
    os.path.join(
        LOG_DIR,
        "anomaly_*.json"
    )
)

if not anomaly_files:
    print("No anomaly result found.")
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
    anomaly_result = json.load(f)

if anomaly_result.get("status") != "ANOMALY":
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
    or not os.path.exists(latest_log)
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

analysis_targets = build_analysis_targets(
    findings,
    configured_targets
)

if not analysis_targets:
    print("No analysis target found.")
    sys.exit(1)


rule_analysis = (
    "## 1. 상태 요약\n"
    "- 규칙 기반 이상 상태가 탐지됨\n"
    "- 탐지 상태: ANOMALY\n\n"
    "## 2. 이상 징후\n"
    + "\n".join(finding_lines)
)


# 이상 항목별 상세 진단 및 LLM 분석
llm_results = {}
detail_cache = {}

for target in analysis_targets:
    finding_id = target["finding_id"]
    target_host = target["target"]
    subject = target["subject"]

    cache_key = (
        target_host,
        subject
    )

    if cache_key not in detail_cache:
        detail_path = collect_service_detail(
            target_host,
            subject
        )

        with open(
            detail_path,
            "r",
            encoding="utf-8"
        ) as f:
            detail_data = f.read()

        detail_cache[cache_key] = {
            "path": detail_path,
            "data": detail_data
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
        f"Detail     : "
        f"{target_host} / "
        f"{subject} -> "
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

    # remediation 정책은 LLM에게 넘기지 않음.
    # LLM은 근거 기반 후보만 제안하고,
    # 허용 여부는 Python Policy가 결정함.
    analysis_input = {
        "finding_id": finding_id,
        "type": target["type"],
        "target": target_host,
        "subject": subject,
        "confirmed_fact": (
            target["confirmed_fact"]
        ),
        "systemd_properties": (
            systemd_properties
        ),
        "interpreted_facts": (
            interpreted_facts
        ),
        "already_collected_data": (
            collected_data
        )
    }

    target_json = json.dumps(
        analysis_input,
        ensure_ascii=False,
        indent=2
    )

    response_schema = (
        build_response_schema(
            finding_id
        )
    )

    prompt = f"""
당신은 Linux 시스템 장애 진단을 지원하는 분석기입니다.

아래 하나의 이상 항목만 분석하세요.

다른 서버, 다른 서비스 또는 다른 이상 항목을
현재 문제의 원인으로 임의로 연결하지 마세요.

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
수집된 로그 안에 정상적인 deactivation 기록이
존재한다는 의미입니다.

이 사실만으로 누가 또는 무엇이
중지를 요청했는지는 판단할 수 없습니다.

current_failed_state,
non_success_result_recorded,
non_zero_exec_status_recorded가 false라는 것은
현재 수집된 해당 필드에서 그 신호가
확인되지 않았다는 의미입니다.

이 값만으로 시스템에 어떠한 오류도
존재하지 않았다고 단정하지 마세요.

already_collected_data의 sources는
현재 분석 입력에 이미 포함된 데이터입니다.

checks의 scope는 다음 기준으로 분류하세요.

existing:
- 이미 제공된 데이터를 같은 범위에서 다시 확인

expanded:
- 이미 제공된 데이터 소스를 사용하지만
  다른 시간 범위 또는 추가 범위를 조회하여
  새로운 정보를 얻는 경우

new:
- 현재 제공되지 않은 새로운 데이터 소스에서
  정보를 확인하는 경우

existing 범위의 확인은 새로운 정보가 아니므로
checks에 포함하지 마세요.

checks에는 실제 원인을 더 좁히기 위해
새로운 정보를 얻을 수 있는 항목만 작성하세요.

remediation_candidates에는
서비스 시작, 재시작, 설정 변경 등
실제 시스템 상태를 변경하는 조치 중
현재 근거를 바탕으로 고려할 가치가 있는 후보만 작성하세요.

각 remediation 후보에는
왜 그 조치를 고려할 수 있는지
basis에 현재 근거를 작성하세요.

근거가 부족한 복구 조치는
억지로 만들지 마세요.

복구 조치의 허용 여부는
LLM이 결정하지 않습니다.
Python Policy가 별도로 판단하므로,
근거가 있는 복구 후보라면
허용 여부를 추측하지 말고 후보로 반환하세요.

반드시 제공된 데이터만 근거로 분석하세요.

과거 로그와 현재 상태를 구분하세요.
가능성을 사실처럼 단정하지 마세요.
원인을 특정할 수 없으면
"확인 필요"라고 작성하세요.

evidence:
- 실제 제공된 데이터에서 확인되는 근거만 작성하세요.
- 존재하지 않는 로그나 사실을 만들어내지 마세요.

cause_candidates:
- 실제 근거를 기반으로 가능한 원인을 작성하세요.
- confirmed_fact 자체를 단순히 다시 표현하지 마세요.
- 서비스 상태와 그 상태가 발생한 원인을 구분하세요.
- 직접적인 근거가 없는 종료 주체를 특정하지 마세요.

checks:
- purpose에는 무엇을 알아내려는지 작성하세요.
- data_source에는 확인할 데이터 소스를 작성하세요.
- scope에는 existing, expanded, new 중 하나를 작성하세요.
- method에는 실제 확인 방법을 작성하세요.
- 시스템 상태를 변경하지 않는 조사만 작성하세요.
- 이미 제공된 데이터를 같은 범위에서
  다시 확인하는 항목은 작성하지 마세요.

SERVICE_DETAIL:

{detail_data}
"""

    structured_analysis = call_ollama(
        prompt,
        response_schema
    )

    if (
        structured_analysis.get("finding_id")
        != finding_id
    ):
        print(
            "Unexpected finding_id from LLM: "
            f"{finding_id}"
        )
        sys.exit(1)

    llm_results[
        finding_id
    ] = structured_analysis


# 최종 분석 결과 생성
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
    finding_id = target["finding_id"]
    target_host = target["target"]
    subject = target["subject"]

    item = llm_results.get(
        finding_id,
        {}
    )

    evidence = get_string_list(
        item,
        "evidence"
    )

    causes = get_string_list(
        item,
        "cause_candidates"
    )

    checks = get_checks(
        item
    )

    remediation_candidates = (
        evaluate_remediation_candidates(
            item,
            target.get(
                "remediation_policy",
                "pending"
            )
        )
    )

    label = (
        f"{target_host} / {subject}"
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
            check_lines.append(
                f"  - 목적: "
                f"{check['purpose']}"
            )

            check_lines.append(
                f"    데이터: "
                f"{check['data_source']} "
                f"({check['scope']})"
            )

            check_lines.append(
                f"    방법: "
                f"{check['method']}"
            )
    else:
        check_lines.append(
            "  - 유효한 추가 확인 항목 없음"
        )

    remediation_lines.append(
        f"- [{label}]"
    )

    if remediation_candidates:
        for candidate in remediation_candidates:
            status = candidate["status"]

            remediation_lines.append(
                f"  - 제안: "
                f"{candidate['description']}"
            )

            remediation_lines.append(
                f"    근거: "
                f"{candidate['basis']}"
            )

            remediation_lines.append(
                f"    상태: "
                f"{status_labels[status]} "
                f"({status})"
            )

            remediation_lines.append(
                f"    정책: "
                f"{candidate['policy_reason']}"
            )
    else:
        remediation_lines.append(
            "  - 근거 기반 복구 조치 후보 없음"
        )


llm_analysis = (
    "## 3. 근거\n"
    + "\n".join(evidence_lines)
    + "\n\n"
    "## 4. 원인 후보\n"
    + "\n".join(cause_lines)
    + "\n\n"
    "## 5. 추가 확인 항목\n"
    + "\n".join(check_lines)
    + "\n\n"
    "## 6. 복구 조치 후보\n"
    + "\n".join(remediation_lines)
)

analysis = (
    f"{rule_analysis}\n\n"
    f"{llm_analysis}\n"
)

timestamp = datetime.now().strftime(
    "%Y%m%d_%H%M%S"
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
    f.write(analysis)

print(f"Diagnostic : {latest_log}")
print(f"Detection  : {latest_anomaly}")
print(f"Output     : {output}")
print()
print(analysis)