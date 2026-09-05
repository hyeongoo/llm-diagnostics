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

    # 향후 host-aware detector가 target을 전달하는 경우
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

    # 여러 서버가 있는데 finding에 target이 없으면 추측하지 않음
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
                "remediation_allowed": False
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
                    "remediation_allowed": False
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
                        "method": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "purpose",
                        "method"
                    ],
                    "additionalProperties": False
                }
            },
            "actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": [
                                "investigation",
                                "remediation"
                            ]
                        },
                        "description": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "type",
                        "description"
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
            "actions"
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
        print(f"Ollama request failed: {e}")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Invalid response from Ollama API.")
        sys.exit(1)

    raw_analysis = result.get("response")

    if not raw_analysis:
        print("Empty response from LLM.")
        sys.exit(1)

    try:
        return json.loads(raw_analysis)

    except json.JSONDecodeError:
        print("Invalid structured response from LLM.")
        sys.exit(1)


def get_list(item, key):
    value = item.get(key, [])

    if not isinstance(value, list):
        return ["확인 필요"]

    values = [
        str(v).strip()
        for v in value
        if str(v).strip()
    ]

    return (
        values
        if values
        else ["확인 필요"]
    )


# 이미 확인된 상태를 다시 확인하는 항목인지 검사
def is_redundant_state_check(purpose, method):
    purpose_lower = purpose.lower()
    method_lower = method.lower()

    redundant_phrases = [
        "현재 상태 확인",
        "서비스 상태 확인",
        "failed 상태 확인",
        "inactive 상태 확인",
        "active 상태 확인",
        "check service status",
        "verify service status",
        "confirm service status"
    ]

    if any(
        phrase in purpose_lower
        for phrase in redundant_phrases
    ):
        return True

    if "systemctl is-active" in method_lower:
        return True

    # systemctl status 결과는 이미 상세 수집 단계에서 확보됨
    if method_lower.strip().startswith(
        "systemctl status"
    ):
        return True

    return False


# 추가 확인 항목 검증
def get_checks(item):
    checks = item.get("checks", [])

    if not isinstance(checks, list):
        return [{
            "purpose": "추가 확인 필요",
            "method": "확인 필요"
        }]

    valid_checks = []

    for check in checks:
        if not isinstance(check, dict):
            continue

        purpose = str(
            check.get("purpose", "")
        ).strip()

        method = str(
            check.get("method", "")
        ).strip()

        if not purpose or not method:
            continue

        if is_redundant_state_check(
            purpose,
            method
        ):
            continue

        valid_checks.append({
            "purpose": purpose,
            "method": method
        })

    if not valid_checks:
        return [{
            "purpose": (
                "현재 수집된 정보만으로 "
                "원인을 더 좁히기 어려움"
            ),
            "method": (
                "추가 진단 데이터 확보 필요"
            )
        }]

    return valid_checks


# investigation으로 잘못 분류된
# 실제 시스템 변경 조치 추가 차단
def looks_like_mutating_action(description):
    text = description.lower()

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


# 안전한 investigation은 허용하고
# 근거 없는 remediation은 차단
def get_safe_actions(item, remediation_allowed):
    actions = item.get("actions", [])

    if not isinstance(actions, list):
        return ["확인 필요"]

    allowed_actions = []

    for action in actions:
        if not isinstance(action, dict):
            continue

        action_type = action.get("type")

        description = str(
            action.get("description", "")
        ).strip()

        if not description:
            continue

        if action_type == "remediation":
            if remediation_allowed:
                allowed_actions.append(
                    description
                )

            continue

        if action_type == "investigation":
            if looks_like_mutating_action(
                description
            ):
                continue

            allowed_actions.append(
                description
            )

    if not allowed_actions:
        return [
            "추가로 안전하게 제안할 조사 조치 없음"
        ]

    return allowed_actions


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
    print("No anomaly detected. AI analysis skipped.")
    sys.exit(0)

latest_log = anomaly_result.get(
    "diagnostic_file"
)

if not latest_log or not os.path.exists(latest_log):
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

    analysis_input = {
        **target,
        "systemd_properties": (
            systemd_properties
        ),
        "interpreted_facts": (
            interpreted_facts
        )
    }

    target_json = json.dumps(
        analysis_input,
        ensure_ascii=False,
        indent=2
    )

    response_schema = build_response_schema(
        finding_id
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

아래 SERVICE_DETAIL은 이상 서비스에 대해
자동 수집한 상세 진단 데이터입니다.

SERVICE_DETAIL에는 다음 정보가 포함될 수 있습니다.

- systemctl show
- systemctl status
- 해당 서비스의 journal 로그

반드시 제공된 데이터만 근거로 분석하세요.

과거 로그와 현재 상태를 구분하세요.
가능성을 사실처럼 단정하지 마세요.
원인을 특정할 수 없으면
"확인 필요"라고 작성하세요.

evidence:
- systemd_properties,
  interpreted_facts,
  SERVICE_DETAIL에서 실제 확인되는 근거만 작성하세요.
- 존재하지 않는 로그나 사실을 만들어내지 마세요.

cause_candidates:
- 실제 근거를 기반으로 가능한 원인을 작성하세요.
- confirmed_fact 자체를 단순히 다시 표현하지 마세요.
- 서비스의 상태와 그 상태가 발생한 원인을 구분하세요.
- 직접적인 근거가 없는 종료 주체를 특정하지 마세요.
- 오류 신호가 확인되지 않았다면
  오류나 crash로 종료됐다고 단정하지 마세요.

checks:
- purpose에는 무엇을 알아내기 위한 확인인지 작성하세요.
- method에는 실제 확인 방법을 작성하세요.
- 이미 수집된 active, inactive, failed 상태 자체를
  다시 확인하는 항목은 작성하지 마세요.
- 이미 제공된 systemctl status 결과를
  단순히 다시 조회하도록 제안하지 마세요.
- 실제 원인을 더 좁힐 수 있는
  새로운 확인만 작성하세요.

actions:

investigation:
- 로그, 설정, 의존성 등
  원인 파악을 위한 안전한 조사 조치

remediation:
- 서비스 시작, 중지, 재시작
- 시스템 재부팅
- 설정 변경
- 파일 수정 또는 삭제 등
  실제 시스템 상태를 변경하는 조치

remediation_allowed가 false이면
remediation 조치를 제안하지 마세요.

응답은 지정된 JSON Schema에 맞춰 작성하세요.
각 필드에는 실제 분석 결과를 작성하세요.

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
action_lines = []

for target in analysis_targets:
    finding_id = target["finding_id"]
    target_host = target["target"]
    subject = target["subject"]

    item = llm_results.get(
        finding_id,
        {}
    )

    evidence = get_list(
        item,
        "evidence"
    )

    causes = get_list(
        item,
        "cause_candidates"
    )

    checks = get_checks(
        item
    )

    actions = get_safe_actions(
        item,
        target.get(
            "remediation_allowed",
            False
        )
    )

    label = (
        f"{target_host} / {subject}"
    )

    evidence_lines.append(
        f"- [{label}]"
    )

    evidence_lines.extend(
        f"  - {value}"
        for value in evidence
    )

    cause_lines.append(
        f"- [{label}]"
    )

    cause_lines.extend(
        f"  - {value}"
        for value in causes
    )

    check_lines.append(
        f"- [{label}]"
    )

    for check in checks:
        check_lines.append(
            f"  - 목적: {check['purpose']}"
        )

        check_lines.append(
            f"    방법: {check['method']}"
        )

    action_lines.append(
        f"- [{label}]"
    )

    action_lines.extend(
        f"  - {value}"
        for value in actions
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
    "## 6. 권장 조치\n"
    + "\n".join(action_lines)
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