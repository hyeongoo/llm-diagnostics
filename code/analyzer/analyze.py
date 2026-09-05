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


# LLM이 분석할 대상을 Rule 결과에서 생성
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


rule_analysis = (
    "## 1. 상태 요약\n"
    "- 규칙 기반 이상 상태가 탐지됨\n"
    "- 탐지 상태: ANOMALY\n\n"
    "## 2. 이상 징후\n"
    + "\n".join(finding_lines)
)

targets_json = json.dumps(
    analysis_targets,
    ensure_ascii=False,
    indent=2
)


prompt = f"""
다음은 규칙 기반으로 이미 확인된 이상 항목과
OpenStack 및 Linux VM의 진단 데이터입니다.

분석 대상은 아래 analysis_targets에 정의된 항목으로 제한됩니다.
analysis_targets에 없는 새로운 이상 항목을 생성하지 마세요.

진단 데이터에 포함된 다른 오류나 로그는
정의된 분석 대상의 원인을 분석하기 위한 근거로만 사용할 수 있습니다.

confirmed_fact는 이미 확인된 사실입니다.
해당 상태 자체를 다시 확인하도록 제안하지 마세요.

반드시 제공된 데이터만 근거로 분석하세요.
근거가 부족하면 "확인 필요"라고 작성하세요.
가능성을 사실처럼 단정하지 마세요.

원인이 확인되지 않은 상태에서 서비스 재시작,
시스템 재부팅 또는 설정 변경을 권장하지 마세요.

각 분석 대상에 대해 다음 세 가지를 작성하세요.

cause_candidates:
- 가능한 원인과 근거
- 원인을 특정할 수 없다면 확인 필요라고 작성

checks:
- confirmed_fact 자체를 다시 확인하지 말 것
- 이상 상태가 발생한 원인을 좁히기 위한 로그,
  상세 정보, 설정, 의존성 등의 확인 항목 작성

actions:
- 현재 데이터만으로 안전하게 제안 가능한 조치 작성
- 원인이 불확실하면 원인 확인 후 조치를 결정하도록 작성
- 근거 없는 재시작, 재부팅, 설정 변경을 제안하지 말 것

반드시 다음 JSON 형식으로만 응답하세요.

{{
  "analyses": [
    {{
      "finding_id": "F1",
      "cause_candidates": ["내용"],
      "checks": ["내용"],
      "actions": ["내용"]
    }}
  ]
}}

analysis_targets:

{targets_json}

진단 데이터:

{diagnostic}
"""

payload = {
    "model": MODEL,
    "prompt": prompt,
    "stream": False,
    "think": False,
    "format": "json",
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
    print("Invalid structured response from LLM.")
    exit(1)


# Rule Engine이 만든 finding_id만 허용
allowed_ids = {
    target["finding_id"]
    for target in analysis_targets
}

llm_results = {}

for item in structured_analysis.get("analyses", []):
    finding_id = item.get("finding_id")

    if finding_id not in allowed_ids:
        continue

    if finding_id in llm_results:
        continue

    llm_results[finding_id] = item


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
    cause_lines.extend(f"  - {value}" for value in causes)

    check_lines.append(f"- [{subject}]")
    check_lines.extend(f"  - {value}" for value in checks)

    action_lines.append(f"- [{subject}]")
    action_lines.extend(f"  - {value}" for value in actions)


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
output = os.path.join(LOG_DIR, f"analysis_{timestamp}.txt")

with open(output, "w", encoding="utf-8") as f:
    f.write(analysis)

print(f"Diagnostic : {latest_log}")
print(f"Detection  : {latest_anomaly}")
print(f"Output     : {output}")
print()
print(analysis)