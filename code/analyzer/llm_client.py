#!/usr/bin/env python3

import json
import sys
import urllib.error
import urllib.request


OLLAMA_URL = "http://192.168.214.1:11434/api/generate"
MODEL = "qwen3:1.7b"


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