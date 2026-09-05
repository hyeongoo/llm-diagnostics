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

# 이상이 없으면 AI 분석하지 않음
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


# 규칙 기반 이상 탐지 결과를 사람이 읽을 수 있는 형태로 변환
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

if not finding_lines:
    finding_lines = ["- 규칙 기반 탐지 결과의 상세 정보 확인 필요"]


# 상태 요약과 이상 징후는 Python이 확정
rule_analysis = (
    "## 1. 상태 요약\n"
    "- 규칙 기반 이상 상태가 탐지됨\n"
    "- 탐지 상태: ANOMALY\n\n"
    "## 2. 이상 징후\n"
    + "\n".join(finding_lines)
)

anomaly_summary = json.dumps(
    {
        "status": anomaly_result.get("status"),
        "findings": findings
    },
    ensure_ascii=False,
    indent=2
)

prompt = f"""
다음은 OpenStack 및 Linux VM에서 수집한 진단 데이터와
규칙 기반 이상 탐지 결과입니다.

규칙 기반 이상 탐지 결과에 포함된 이상 상태는 이미 확정된 사실입니다.
이상 여부나 전체 시스템의 정상/비정상 상태를 다시 판단하지 마세요.

반드시 제공된 데이터만 근거로 분석하세요.
진단 데이터에 없는 상태나 수치를 임의로 만들어내지 마세요.
확실하지 않은 내용은 "확인 필요"라고 표시하세요.
응답은 한국어로 작성하고 "None"을 사용하지 마세요.

분석 원칙:
- 탐지된 이상 상태와 그 원인을 구분하세요.
- 이상 상태가 확인되었다는 이유만으로 원인이 확인되었다고 판단하지 마세요.
- 서로 다른 이상 항목 사이의 관계가 데이터로 확인되지 않았다면 서로 관련 있다고 추론하지 마세요.
- 이미 규칙 기반으로 확인된 상태를 단순히 다시 확인하라고 제안하지 마세요.
- 원인을 판단하기 위해 필요한 로그, 서비스 상세 상태, 설정 등의 추가 확인을 우선 제안하세요.
- 근거가 충분하지 않은 상태에서 서비스 재시작, 시스템 재부팅, 설정 변경을 권장하지 마세요.
- 재시작이나 설정 변경이 필요한지는 추가 확인 결과를 바탕으로 결정하도록 작성하세요.
- 규칙 기반 탐지 결과에 actual 값이 존재하는 경우 해당 상태 자체는 이미 확인된 사실이므로 다시 확인하도록 제안하지 마세요.
- 추가 확인 항목은 "현재 상태 확인"이 아니라 "해당 상태가 발생한 원인 확인"을 목적으로 작성하세요.
- 서비스 이상인 경우 서비스 상세 정보, 해당 서비스의 journal 로그, 설정 또는 의존성 등 원인 분석에 필요한 정보를 우선 확인하세요.

반드시 아래 3개 항목만 출력하세요.
상태 요약이나 이상 징후를 다시 출력하지 마세요.

## 3. 원인 후보
- 각 이상 항목별로 가능한 원인과 현재 데이터에서 확인되는 근거를 작성
- 현재 데이터만으로 원인을 특정할 수 없다면 "확인 필요"라고 명시
- 가능성을 사실처럼 단정하지 말 것

## 4. 추가 확인 항목
- 이미 확인된 actual 상태를 다시 확인하지 말 것
- 해당 이상이 발생한 원인을 좁히기 위해 필요한 항목만 작성
- 서비스 이상이라면 서비스 상세 상태, 해당 서비스의 journal 로그, 설정 및 의존성 등 원인 분석에 필요한 정보를 작성

## 5. 권장 조치
- 원인이 아직 확인되지 않았다면 즉시 복구 작업을 제안하지 말고 원인 분석을 우선하도록 작성
- 추가 확인 결과로 원인이 확인된 경우에만 재시작, 설정 변경 등의 복구 조치를 제안
- 현재 데이터만으로 근거가 없는 재시작, 재부팅, 설정 변경은 제안하지 말 것

규칙 기반 이상 탐지 결과:

{anomaly_summary}

진단 데이터:

{diagnostic}
"""

payload = {
    "model": MODEL,
    "prompt": prompt,
    "stream": False,
    "think": False,
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

llm_analysis = result["response"].strip()

# Rule 기반 결과 + LLM 분석 결과 결합
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