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

files = glob.glob(os.path.join(LOG_DIR, "diagnostic_*.log"))

if not files:
    print("No diagnostic log found.")
    exit(1)

latest_log = max(files, key=os.path.getmtime)

with open(latest_log, "r", encoding="utf-8") as f:
    diagnostic = f.read()

prompt = f"""
다음은 OpenStack 및 Linux VM에서 수집한 진단 데이터입니다.

반드시 제공된 데이터만 근거로 분석하세요.
진단 데이터에 없는 상태나 수치를 임의로 추론하지 마세요.
확실하지 않은 내용은 "확인 필요"라고 표시하세요.
응답은 한국어로 작성하고 "None"을 사용하지 마세요.

중요:
이상 징후가 발견되지 않은 경우 존재하지 않는 장애 원인을 추론하지 마세요.
추가 확인이 필요하지 않다면 불필요한 확인 항목을 생성하지 마세요.
정상 상태에서는 재부팅, 서비스 재시작, 설정 변경 등의 조치를 제안하지 마세요.
위 규칙에 대한 설명을 출력하지 말고 분석 결과만 작성하세요.

운영자가 빠르게 상태를 판단할 수 있도록 반드시 다음 형식으로 작성하세요.

## 1. 상태 요약
- 전체 시스템 상태를 간단히 요약
- 위험도를 Low / Medium / High 중 하나로 표시

## 2. 이상 징후
- 실제로 발견된 이상 징후만 작성
- 이상 징후가 없으면 "- 특이사항 없음" 한 줄만 작성
- "None", "발견된 이상 징후:" 같은 표현은 출력하지 말 것

## 3. 원인 후보
- 이상 징후가 있을 경우 가능한 원인과 판단 근거 작성
- 이상 징후가 없으면 "- 해당 없음" 한 줄만 작성
- 지시사항 자체를 답변에 포함하지 말 것

## 4. 추가 확인 항목
- 실제로 추가 확인이 필요한 항목만 작성
- 추가 확인이 필요하지 않으면 "- 없음" 한 줄만 작성

## 5. 권장 조치
- 현재 진단 결과에 필요한 조치만 작성
- 정상 상태라면 상태 유지 또는 모니터링 수준의 조치만 작성
- 프롬프트의 규칙이나 금지사항 자체를 답변에 출력하지 말 것

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

analysis = result["response"]

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output = os.path.join(LOG_DIR, f"analysis_{timestamp}.txt")

with open(output, "w", encoding="utf-8") as f:
    f.write(analysis)

print(f"Input  : {latest_log}")
print(f"Output : {output}")
print()
print(analysis)