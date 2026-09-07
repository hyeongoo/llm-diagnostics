#!/bin/bash

BASE_DIR="$HOME/aiops-openstack"
DETAIL_LOG="$BASE_DIR/logs/run_detail_$(date +%Y%m%d_%H%M%S).log"

# 1. 상태 및 로그 수집
COLLECT_OUTPUT=$(
    "$BASE_DIR/collector/collect_all.sh" 2>&1
)
COLLECT_STATUS=$?

{
    echo "===== 1. 상태 및 로그 수집 ====="
    echo "$COLLECT_OUTPUT"
    echo
} >> "$DETAIL_LOG"

if [ $COLLECT_STATUS -ne 0 ]; then
    echo "상태 및 로그 수집 실패"
    echo "$COLLECT_OUTPUT"
    exit 1
fi


# 2. 이상 상태 탐지
DETECT_OUTPUT=$(
    python3 "$BASE_DIR/analyzer/detect_anomaly.py" 2>&1
)
DETECT_STATUS=$?

{
    echo "===== 2. 이상 상태 탐지 ====="
    echo "$DETECT_OUTPUT"
    echo
} >> "$DETAIL_LOG"


# 정상 상태
if [ $DETECT_STATUS -eq 0 ]; then
    echo "===== 3. AI 진단 분석 ====="
    echo
    echo "## 진단 결과"
    echo "- 상태: NORMAL"
    echo "- 이상 상태가 탐지되지 않아 AI 분석을 생략했습니다."
    echo
    echo "===== Diagnosis Complete ====="
    exit 0
fi


# 탐지 과정 자체 실패
if [ $DETECT_STATUS -ne 2 ]; then
    echo "이상 상태 탐지 실패"
    echo "$DETECT_OUTPUT"
    exit 1
fi


# 3. AI 진단 분석
ANALYZE_OUTPUT=$(
    python3 "$BASE_DIR/analyzer/analyze.py" 2>&1
)
ANALYZE_STATUS=$?

{
    echo "===== 3. AI 진단 분석 ====="
    echo "$ANALYZE_OUTPUT"
    echo
} >> "$DETAIL_LOG"


if [ $ANALYZE_STATUS -ne 0 ]; then
    echo "AI 진단 분석 실패"
    echo "$ANALYZE_OUTPUT"
    exit 1
fi


# 운영자에게는 최종 핵심 결과만 출력
echo "===== 3. AI 진단 분석 ====="
echo

echo "$ANALYZE_OUTPUT" | awk '
    /^## 진단 결과/ {
        show = 1
    }

    show {
        print
    }
'

echo
echo "===== Diagnosis Complete ====="