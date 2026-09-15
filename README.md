## 핵심 문제와 설계 판단

---

**배경 및 목적:** 기존 AWS·OpenStack 인프라 경험을 AI 활용 영역으로 확장하기 위해, OpenStack 리소스와 Private Instance의 상태·로그를 자동 수집하고 규칙 기반 이상 탐지와 LLM 기반 원인 해석·대응 제안을 연결한 클라우드 운영 진단 자동화 환경 구현.

**문제 인식:** LLM의 근거 생성·로그 해석 오류 발생. 이를 보완하는 의미 검증 규칙이 늘면서 코드 복잡도와 답변 제한도 증가.

**설계 판단:** 관측 데이터를 Observation으로 구조화하고 해석과 분리. Python은 상태 판정·구조·참조 검증, LLM은 장애 해석·대응 제안을 담당.

**결과와 한계:** 두 장애 유형의 진단 흐름 확인. 관측 데이터·LLM 원본·검증 결과를 Trace에 저장해 비교 가능하도록 구성. 의미 해석 오류가 남아 대응 제안은 운영자 검토 전제.
---

### 전체 환경 구성

**아키텍처 다이어그램**

![아키텍처 다이어그램.png](./picture/아키텍처다이어그램.png)

---

### 주요 기술 선택

| 구분 | 기술 | 선택 이유 |
| --- | --- | --- |
| Platform | OpenStack | 기존 IaC 환경 활용, 추가 퍼블릭 클라우드 비용 없이 반복 실습 |
| Collection | Shell Script | OpenStack CLI·SSH·Linux 명령 기반 상태/로그 수집 |
| Analysis | Python | 상태 비교, Observation 구조화, LLM 호출·검증 및 결과 처리 |
| LLM | Ollama + Qwen3 1.7B | 제한된 로컬 자원에서 실행 가능한 한국어·구조화 출력 모델 |

모델 선정 기준:

**무료 로컬 실행 / CPU 실행 / 저장공간 / 한국어 / 운영 분석 / Tool 확장성**

> 제한된 로컬 CPU 환경에서 반복 테스트가 가능하면서 한국어 처리와 구조화된 진단 출력이 가능한 모델을 우선 고려해 Qwen3 1.7B를 초기 모델로 선정.

---

## 클라우드 상태 및 로그 수집

![진단 흐름도.png](./picture/진단%20흐름도.png)

### OpenStack 인프라 상태 수집

![OpenStack 상태 수집 결과.png](./picture/OpenStack%20상태%20수집%20결과.png)

---

### Private 인스턴스 상태 및 오류 로그 수집

![Private Instance 상태 및 오류 로그 수집 결과.png](./picture/Private%20Instance%20상태%20및%20오류%20로그%20수집%20결과.png)



---

## 주요 문제 해결 과정

### ① LLM 진단의 환각 및 불안정한 추론

---

| 구분 | 내용 |
| --- | --- |
| **문제** | LLM이 근거 문장을 직접 생성하면서 관측 사실과 추론이 섞이고, Host·Service 정보를 혼동. 이를 보완하는 Python의 의미 검증이 늘어나면서 코드 복잡도 증가 및 답변의 과도한 제한 발생. |
| **판단** | 의미 검증 규칙을 추가하는 방식은 코드 복잡도를 높이고 답변을 과도하게 제한. 규칙을 계속 늘리는 대신, 근거를 실제 Observation으로 고정하고 LLM의 해석을 분리하는 방식으로 전환. 의미 해석의 정확성을 보장하기보다 근거 출처와 오류 발생 단계를 확인할 수 있도록 설계. |
| **적용** | ① 수집 데이터를 Observation으로 구조화하고 ID 부여
② Host·Service별 분석 대상 분리 및 JSON Schema 기반 출력 적용
③ Python에서 출력 구조와 실제 Observation 참조 검증
④ Report에 진단 결과, Trace에 Observation·LLM 원본·검증 결과 저장 |
| **결과·한계** | 근거 출처 확인과 LLM 원본 응답·Python 검증 결과의 비교가 가능한 구조 마련. 의미 해석 오류는 남아 있어 대응 제안은 운영자 검토를 전제로 구성. |

![문제1.png](./picture/문제1.png)


### ② Private Instance 직접 접근 불가

---

| 구분 | 내용 |
| --- | --- |
| **문제** | 당시 네트워크 구성에서 OpenStack Controller의 Private Instance에 직접 SSH 접속 실패로 내부 상태·로그 수집 불가. |
| **판단** | Bastion을 경유하는 SSH 접속 경로를 구성하고, 접속 설정은 SSH Config에 모아 수집 스크립트에서도 재사용하도록 구성. |
| **적용** | ① ProxyJump를 통한 Bastion 경유 접속 구성
② SSH Config에 Bastion·Private Instance별 SSH 키 경로와 접속 별칭 등록
③ 수집 스크립트에 동일한 접속 별칭 적용 |
| **결과** | 접속 별칭을 통한 Private Instance 접근 및 상태·로그 수집 확인. SSH Config의 접속 설정을 수집 스크립트에서 일관되게 재사용. |

![문제2.png](./picture/문제2.png)


### ③ LLM 실행 환경 분리 및 API 연결 문제 해결

---

| 구분 | 내용 |
| --- | --- |
| **문제** | Controller VM의 메모리 16GB 중 약 14GB 사용으로 LLM 동시 실행에 부담. Windows Host로 추론을 분리했으나 Controller VM의 API 요청에서 Timeout 발생. |
| **판단** | Windows Host에서 LLM을 실행해 Controller의 수집·분석 요청과 역할 분리. 연결 오류는 로컬 API, 바인딩, 외부 접근을 순서대로 확인해 원인 범위를 좁힘. |
| **확인·적용** | ① Windows의 localhost API에서 모델 조회 성공 확인
② Host-Only IP로 바인딩 후 Listen 상태와 Windows 내 해당 IP 호출 성공 확인 
      → Controller에서만 Timeout 지속
③ Controller IP의 TCP 11434 허용 규칙 추가 후에도 실패해 애플리케이션별 규칙 점검
④ 활성화된 `ollama.exe` Inbound Block 발견 및 비활성화 |
| **결과** | 차단 규칙 비활성화 전후 Controller VM에서 동일한 `curl` 요청을 비교해 Timeout → 정상 JSON 응답 전환 확인. Qwen3 1.7B API 호출 성공 및 Controller IP로 접근 허용 범위 제한. |

![문제3.png](./picture/문제3.png)

---

## 구현 결과 및 검증

---

| 테스트 | 재현 방법 | 검증 범위 |
| --- | --- | --- |
| 서비스 실행 실패 | `/bin/false` 실행으로 비정상 종료 재현 | 이상 탐지부터 LLM 진단 출력까지 전체 흐름 확인 |
| 서비스 시작 Timeout | `/bin/sleep 30`, 시작 제한시간 5초 설정 | 이상 탐지부터 LLM 진단 출력까지 전체 흐름 확인 |

두 테스트는 진단 파이프라인의 동작을 확인한 것으로, LLM의 원인 해석과 대응 제안이 모두 정확함을 의미하지는 않음.

![서비스 상태 수집결과](./picture/서비스%20상태%20수집결과.png)

Timeout 테스트 서비스의 상태 수집 결과

![LLM진단 결과](./picture/LLM진단%20결과.png)

LLM 진단 출력 — Timeout 근거는 제시했으나, 실행 명령의 30초를 제한시간으로 오해

---

## 기술 선택과 적용 범위

| 기술 | 선택 이유와 적용 범위 |
| --- | --- |
| OpenStack | 기존에 구축한 환경을 활용해 리소스 상태 수집과 Private Instance 진단 실습 수행 |
| Shell Script | OpenStack CLI·SSH·Linux 명령을 연결해 수집 절차 자동화 |
| Python | 상태 비교, Observation 구조화, LLM 호출·검증, 결과 저장 담당 |
| Ollama + Qwen3 1.7B | 로컬 CPU 환경에서 실행하며 한국어 진단과 구조화 출력의 적용 가능성을 확인하기 위한 초기 모델 |

---

## 한계 및 개선 방향

**현재 한계**

- Qwen3 1.7B가 /bin/false의 비정상 종료를 미실행으로 해석하는 등 systemd 의미 해석 오류가 남아 있음
- LLM의 대응 제안은 운영자 검토를 전제로 하며, 실제 조치는 자동 실행하지 않음
- 단일 실습 환경 중심의 Desired State 구성

**확장 계획**

- 실제 관측 결과를 기준으로, 동일 입력·프롬프트에서 모델별 해석 정확도와 응답 시간을 비교해 모델 선정 및 프롬프트 개선에 반영
- 실행 단위 Run ID를 도입해 수집·탐지·분석 결과의 연결을 명확히 하기
- 다중 Host와 역할별 Desired State로 적용 범위 확장
- 진단 품질 검증 후 Runbook 기반 운영자 승인형 복구 검토