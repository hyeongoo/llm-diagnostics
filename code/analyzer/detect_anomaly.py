#!/usr/bin/env python3

import glob
import json
import os
import re
import sys
from datetime import datetime

BASE_DIR = os.path.expanduser("~/aiops-openstack")
LOG_DIR = os.path.join(BASE_DIR, "logs")
DESIRED_STATE_FILE = os.path.join(BASE_DIR, "config", "desired_state.json")

files = glob.glob(os.path.join(LOG_DIR, "diagnostic_*.log"))

if not files:
    print("No diagnostic log found.")
    sys.exit(1)

latest_log = max(files, key=os.path.getmtime)

with open(DESIRED_STATE_FILE, "r", encoding="utf-8") as f:
    desired_state = json.load(f)

with open(latest_log, "r", encoding="utf-8") as f:
    diagnostic = f.read()


def get_service_status(service_name, log_data):
    pattern = rf"===== {re.escape(service_name.upper())} STATUS =====\s*\n([^\r\n]+)"
    match = re.search(pattern, log_data)

    if not match:
        return None

    return match.group(1).strip().lower()


def get_failed_services(log_data):
    pattern = r"===== FAILED SERVICES =====(.*?)(?====== |\Z)"
    match = re.search(pattern, log_data, re.DOTALL)

    if not match:
        return []

    section = match.group(1)

    failed_services = re.findall(
        r"^[●\s]*([^\s]+)\s+\S+\s+failed\s+failed\s+",
        section,
        re.MULTILINE
    )

    return failed_services


findings = []

# Desired State에 정의된 서비스 상태 비교
services = desired_state.get("services", {})

for service, expected_status in services.items():
    expected = str(expected_status).strip().lower()
    actual = get_service_status(service, diagnostic)

    if actual is None:
        findings.append({
            "type": "service_state_mismatch",
            "service": service,
            "expected": expected,
            "actual": "unknown"
        })

    elif actual != expected:
        findings.append({
            "type": "service_state_mismatch",
            "service": service,
            "expected": expected,
            "actual": actual
        })


# Failed Service 개수 확인
system_state = desired_state.get("system", {})
max_failed_services = system_state.get("max_failed_services")

if max_failed_services is not None:
    failed_services = get_failed_services(diagnostic)
    failed_count = len(failed_services)

    if failed_count > max_failed_services:
        findings.append({
            "type": "failed_services_exceeded",
            "expected_max": max_failed_services,
            "actual": failed_count,
            "services": failed_services
        })


status = "ANOMALY" if findings else "NORMAL"

result = {
    "status": status,
    "diagnostic_file": latest_log,
    "findings": findings
}

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output = os.path.join(LOG_DIR, f"anomaly_{timestamp}.json")

with open(output, "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

print(f"Input  : {latest_log}")
print(f"Output : {output}")
print()
print(f"Status: {status}")

for finding in findings:
    if finding["type"] == "service_state_mismatch":
        print(
            f"- {finding['service']}: "
            f"expected={finding['expected']}, "
            f"actual={finding['actual']}"
        )

    elif finding["type"] == "failed_services_exceeded":
        print(
            f"- failed_services: "
            f"expected_max={finding['expected_max']}, "
            f"actual={finding['actual']}"
        )

        for service in finding["services"]:
            print(f"  - {service}")

if status == "ANOMALY":
    sys.exit(2)

sys.exit(0)