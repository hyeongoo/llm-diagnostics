#!/usr/bin/env python3

import glob
import json
import os
import re
import sys
from datetime import datetime


BASE_DIR = os.path.expanduser("~/aiops-openstack")
LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

DESIRED_STATE_FILE = os.path.join(
    BASE_DIR,
    "config",
    "desired_state.json"
)


# 최신 Diagnostic 파일 확인
def get_latest_diagnostic():
    files = glob.glob(
        os.path.join(
            LOG_DIR,
            "diagnostic_*.log"
        )
    )

    if not files:
        print(
            "No diagnostic log found."
        )
        sys.exit(1)

    return max(
        files,
        key=os.path.getmtime
    )


# Desired State 읽기
def load_desired_state():
    if not os.path.exists(
        DESIRED_STATE_FILE
    ):
        print(
            "Desired state file not found: "
            f"{DESIRED_STATE_FILE}"
        )
        sys.exit(1)

    with open(
        DESIRED_STATE_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


# Diagnostic에서 Host별 영역 분리
def get_host_sections(log_data):
    pattern = re.compile(
        r"^===== HOST STATUS: (.+?) =====\s*$",
        re.MULTILINE
    )

    matches = list(
        pattern.finditer(
            log_data
        )
    )

    if not matches:
        return {}

    host_sections = {}

    for index, match in enumerate(
        matches
    ):
        host = (
            match.group(1)
            .strip()
        )

        start = match.end()

        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(log_data)
        )

        if not host:
            continue

        # 같은 Host 블록이 중복되면
        # 임의로 합치지 않고 실패 처리
        if host in host_sections:
            print(
                "Duplicate host section found "
                "in diagnostic: "
                f"{host}"
            )
            sys.exit(1)

        host_sections[
            host
        ] = log_data[
            start:end
        ]

    return host_sections


# 특정 Service의 현재 상태 확인
def get_service_status(
    service_name,
    host_log
):
    pattern = (
        rf"===== "
        rf"{re.escape(service_name.upper())} "
        rf"STATUS =====\s*\n"
        rf"([^\r\n]+)"
    )

    match = re.search(
        pattern,
        host_log
    )

    if not match:
        return None

    return (
        match.group(1)
        .strip()
        .lower()
    )


# Host의 Failed Service 목록 추출
def get_failed_services(
    host_log
):
    pattern = (
        r"===== FAILED SERVICES ====="
        r"(.*?)"
        r"(?====== |\Z)"
    )

    match = re.search(
        pattern,
        host_log,
        re.DOTALL
    )

    if not match:
        return []

    section = match.group(1)

    failed_services = re.findall(
        (
            r"^[●\s]*"
            r"([^\s]+)"
            r"\s+\S+"
            r"\s+failed"
            r"\s+failed"
            r"\s+"
        ),
        section,
        re.MULTILINE
    )

    return failed_services


# 하나의 Host만 대상으로 Rule 검사
def detect_host_findings(
    host,
    host_log,
    desired_state
):
    findings = []


    # Desired State에 정의된
    # Service 상태 비교
    services = desired_state.get(
        "services",
        {}
    )

    for (
        service,
        expected_status
    ) in services.items():

        expected = (
            str(expected_status)
            .strip()
            .lower()
        )

        actual = get_service_status(
            service,
            host_log
        )

        if actual is None:
            findings.append({
                "type":
                    "service_state_mismatch",

                "target":
                    host,

                "service":
                    service,

                "expected":
                    expected,

                "actual":
                    "unknown"
            })

        elif actual != expected:
            findings.append({
                "type":
                    "service_state_mismatch",

                "target":
                    host,

                "service":
                    service,

                "expected":
                    expected,

                "actual":
                    actual
            })


    # Failed Service 개수 확인
    system_state = (
        desired_state.get(
            "system",
            {}
        )
    )

    max_failed_services = (
        system_state.get(
            "max_failed_services"
        )
    )

    if max_failed_services is not None:
        failed_services = (
            get_failed_services(
                host_log
            )
        )

        failed_count = len(
            failed_services
        )

        if (
            failed_count
            > max_failed_services
        ):
            findings.append({
                "type":
                    "failed_services_exceeded",

                "target":
                    host,

                "expected_max":
                    max_failed_services,

                "actual":
                    failed_count,

                "services":
                    failed_services
            })

    return findings


# Console 출력
def print_finding(finding):
    target = finding.get(
        "target",
        "unknown"
    )

    finding_type = finding.get(
        "type"
    )

    if (
        finding_type
        == "service_state_mismatch"
    ):
        print(
            f"- [{target}] "
            f"{finding['service']}: "
            f"expected="
            f"{finding['expected']}, "
            f"actual="
            f"{finding['actual']}"
        )

    elif (
        finding_type
        == "failed_services_exceeded"
    ):
        print(
            f"- [{target}] "
            f"failed_services: "
            f"expected_max="
            f"{finding['expected_max']}, "
            f"actual="
            f"{finding['actual']}"
        )

        for service in finding[
            "services"
        ]:
            print(
                f"  - {service}"
            )


# -------------------------
# 탐지 시작
# -------------------------

latest_log = (
    get_latest_diagnostic()
)

desired_state = (
    load_desired_state()
)


with open(
    latest_log,
    "r",
    encoding="utf-8"
) as f:
    diagnostic = f.read()


# Host별 Diagnostic 분리
host_sections = (
    get_host_sections(
        diagnostic
    )
)


if not host_sections:
    print(
        "No host-aware sections found "
        "in diagnostic. "
        "Expected header format: "
        "===== HOST STATUS: TARGET ====="
    )

    sys.exit(1)


findings = []


# Host마다 독립적으로 Rule 검사
for (
    host,
    host_log
) in host_sections.items():

    host_findings = (
        detect_host_findings(
            host,
            host_log,
            desired_state
        )
    )

    findings.extend(
        host_findings
    )


status = (
    "ANOMALY"
    if findings
    else "NORMAL"
)


result = {
    "status":
        status,

    "diagnostic_file":
        latest_log,

    "hosts":
        list(
            host_sections.keys()
        ),

    "findings":
        findings
}


timestamp = (
    datetime.now()
    .strftime(
        "%Y%m%d_%H%M%S"
    )
)


output = os.path.join(
    LOG_DIR,
    f"anomaly_{timestamp}.json"
)


with open(
    output,
    "w",
    encoding="utf-8"
) as f:
    json.dump(
        result,
        f,
        ensure_ascii=False,
        indent=2
    )


print(
    f"Input  : {latest_log}"
)

print(
    f"Output : {output}"
)

print()

print(
    f"Status: {status}"
)


for finding in findings:
    print_finding(
        finding
    )


if status == "ANOMALY":
    sys.exit(2)


sys.exit(0)