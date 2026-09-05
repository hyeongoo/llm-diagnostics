#!/usr/bin/env python3

import glob
import json
import os
import urllib.request
from datetime import datetime

BASE_DIR = os.path.expanduser("~/aiops-openstack")
LOG_DIR = os.path.join(BASE_DIR, "logs")

OLLAMA_URL = "http://192.168.214.1:11434/api/generate"
MODEL = "qwen3:1.7b"

# 가장 최근 이상 탐지 결과 확인
anomaly_files = glob.glob(os.path.join(LOG_DIR, "anomaly_*.json"))

if not anomaly_files:
    print("No anomaly result found.")
    exit(1)

latest_anomaly = max(anomaly_files, key=os.path.getmtime)

with open(latest_anomaly, "r", encoding="utf-8") as f:
    anomaly_result = json.load(f)

if anomaly_result.get("status") != "ANOMALY":
    print("No anomaly detected. AI analysis skipped.")
    exit(0)

# 이상 탐지에 사용된 Diagnostic 파일 확인
latest_log = anomaly_result.get("diagnostic_file")

if not latest_log or not os.path.exists(latest_log):
    print("Diagnostic log referenced by anomaly result not found.")
    exit(1)

with open(latest_log, "r", encoding="utf-8") as f:
    diagnostic = f.read()

findings = anomaly_result.get("findings", [])


# Rule 기반 결과를 화면 출력용 형태로 변환
def format_finding(finding):
    finding_type = finding.get("type")

    if finding_type == "service_state_mismatch":
        return (
            f"- {finding.get('service')}: "
            f"expected={finding.get('expected')}, "
            f"actual={finding.get('actual')}"
        )

    if finding_type == "failed_services_exceeded":
        services = finding.get("services", [])
        service_list = ", ".join(services) if services else "확인 필요"

        return (
            f"- Failed Services: "
            f"expected_max={finding.get('expected_max')}, "
            f"actual={finding.get('actual')} "
            f"({service_list})"
        )

    return f"- {json.dumps(finding, ensure_ascii=False)}"


finding_lines = [format_finding(finding) for finding in findings]


# Rule Engine 결과를 LLM 분석 대상으로 변환
analysis_targets = []
target_number = 1

for finding in findings:
    finding_type = finding.get("type")

    if finding_type == "service_state_mismatch":
        analysis_targets.append({
            "finding_id": f"F{target_number}",
            "type": "service_state_mismatch",
            "subject": finding.get("service"),
            "confirmed_fact": (
                f"expected={finding.get('expected')}, "
                f"actual={finding.get('actual')}"
            )
        })
        target_number += 1

    elif finding_type == "failed_services_exceeded":
        for service in finding.get("services", []):
            analysis_targets.append({
                "finding_id": f"F{target_number}",
                "type": "failed_service",
                "subject": service,
                "confirmed_fact": "systemctl --failed에 포함됨"
            })
            target_number += 1

if not analysis_targets:
    print("No analysis target found.")
    exit(1)


# Diagnostic에서 해당 이상 항목과 직접 관련된 근거만 추출
def extract_related_evidence(log_data, subject, context_lines=2, max_lines=30):
    lines = log_data.splitlines()

    subject_lower = subject.lower()
    keywords = {subject_lower}

    # systemd 서비스라면 .service를 제외한 이름도 검색
    if subject_lower.endswith(".service"):
        keywords.add(subject_lower[:-8])

    matched_indexes = []

    for index, line in enumerate(lines):
        line_lower = line.lower()

        if any(keyword in line_lower for keyword in keywords):
            start = max(0, index - context_lines)
            end = min(len(lines), index + context_lines + 1)

            matched_indexes.extend(range(start, end))

    # 중복 제거 및 기존 순서 유지
    unique_indexes = []
    seen = set()

    for index in matched_indexes:
        if index not in seen:
            seen.add(index)
            unique_indexes.append(index)

    selected_lines = [
        lines[index]
        for index in unique_indexes[:max_lines]
    ]

    if not selected_lines:
        return "직접 관련된 추가 로그 근거 없음"

    return "\n".join(selected_lines)


rule_analysis = (
    "## 1. 상태 요약\n"
    "- 규칙 기반 이상 상태가 탐지됨\n"
    "- 탐지 상태: ANOMALY\n\n"
    "## 2. 이상 징후\n"
    + "\n".join(finding_lines)
)


# 이상 항목별 LLM 분석
llm_results = {}

for target in analysis_targets:
    finding_id = target["finding_id"]
    subject = target["subject"]

    related_evidence = extract_related_evidence(
        diagnostic,
        subject
    )

    target_json = json.dumps(
        target,
        ensure_ascii=False,
        indent=2
    )
    
    response_schema = {
        "type": "object",
        "properties": {
            "finding_id": {
                "type": "string",
                "enum": [finding_id]
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
                    "type": "string"
                }
            },
            "actions": {
                "type": "array",
                "items": {
                    "type": "string"
                }
            }
        },
        "required": [
            "finding_id",
            "cause_candidates",
            "checks",
            "actions"
        ],
        "additionalProperties": False
    }

    prompt = f"""
다음 하나의 이상 항목만 분석하세요.

다른 이상 항목이 존재할 수 있지만 현재 분석 범위에는 포함되지 않습니다.
다른 서비스나 다른 이상 항목을 현재 문제의 원인으로 임의로 연결하지 마세요.

분석 대상:

{target_json}

confirmed_fact는 규칙 기반 탐지기가 이미 확인한 현재 상태입니다.
confirmed_fact 자체를 다시 확인하도록 제안하지 마세요.

아래 related_evidence는 현재 분석 대상과 직접 관련된 진단 데이터만 추출한 것입니다.

related_evidence에 과거 오류 로그가 포함되어 있을 수 있습니다.
과거 오류 기록이 존재한다는 사실과 현재 장애 상태를 구분하세요.
과거 오류 기록만으로 현재 상태를 단정하지 마세요.

반드시 제공된 정보만 근거로 분석하세요.
근거가 부족한 경우 "확인 필요"라고 작성하세요.
가능성을 사실처럼 단정하지 마세요.

checks에서는 현재 상태가 active/inactive/failed인지 다시 확인하도록 제안하지 마세요.
단, 장애 원인을 확인하기 위한 서비스 상세 정보나 로그 확인은 제안할 수 있습니다.
예를 들어 systemctl status 또는 journalctl 확인은
서비스가 왜 해당 상태가 되었는지 분석하기 위한 목적으로 사용할 수 있습니다.

원인이 확인되지 않은 경우 서비스 재시작,
시스템 재부팅 또는 설정 변경을 바로 권장하지 마세요.

응답은 지정된 JSON Schema에 맞춰 작성하세요.
각 필드에는 실제 분석 결과를 작성하고 예시나 placeholder 문구를 출력하지 마세요.

관련 근거:

{related_evidence}
"""

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

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )

    with urllib.request.urlopen(request, timeout=300) as response:
        result = json.loads(response.read().decode("utf-8"))

    raw_analysis = result["response"]

    try:
        structured_analysis = json.loads(raw_analysis)
    except json.JSONDecodeError:
        print(f"Invalid structured response from LLM: {finding_id}")
        exit(1)

    # 요청한 finding_id와 다른 결과는 사용하지 않음
    if structured_analysis.get("finding_id") != finding_id:
        print(f"Unexpected finding_id from LLM: {finding_id}")
        exit(1)

    llm_results[finding_id] = structured_analysis


def get_list(item, key):
    value = item.get(key, [])

    if not isinstance(value, list):
        return ["확인 필요"]

    values = [
        str(v).strip()
        for v in value
        if str(v).strip()
    ]

    return values if values else ["확인 필요"]


cause_lines = []
check_lines = []
action_lines = []

for target in analysis_targets:
    finding_id = target["finding_id"]
    subject = target["subject"]

    item = llm_results.get(finding_id, {})

    causes = get_list(item, "cause_candidates")
    checks = get_list(item, "checks")
    actions = get_list(item, "actions")

    cause_lines.append(f"- [{subject}]")
    cause_lines.extend(
        f"  - {value}"
        for value in causes
    )

    check_lines.append(f"- [{subject}]")
    check_lines.extend(
        f"  - {value}"
        for value in checks
    )

    action_lines.append(f"- [{subject}]")
    action_lines.extend(
        f"  - {value}"
        for value in actions
    )


llm_analysis = (
    "## 3. 원인 후보\n"
    + "\n".join(cause_lines)
    + "\n\n"
    "## 4. 추가 확인 항목\n"
    + "\n".join(check_lines)
    + "\n\n"
    "## 5. 권장 조치\n"
    + "\n".join(action_lines)
)

analysis = f"{rule_analysis}\n\n{llm_analysis}\n"

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output = os.path.join(
    LOG_DIR,
    f"analysis_{timestamp}.txt"
)

with open(output, "w", encoding="utf-8") as f:
    f.write(analysis)

print(f"Diagnostic : {latest_log}")
print(f"Detection  : {latest_anomaly}")
print(f"Output     : {output}")
print()
print(analysis)