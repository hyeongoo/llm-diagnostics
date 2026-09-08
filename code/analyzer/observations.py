#!/usr/bin/env python3


def extract_section_lines(
    detail_data,
    section_name
):
    header = (
        f"===== {section_name} ====="
    )

    result = []
    in_section = False

    for line in detail_data.splitlines():
        stripped = line.strip()

        if stripped == header:
            in_section = True
            continue

        if (
            in_section
            and stripped.startswith(
                "====="
            )
            and stripped.endswith(
                "====="
            )
        ):
            break

        if (
            in_section
            and stripped
        ):
            result.append(
                stripped
            )

    return result


def build_observation_catalog(
    confirmed_fact,
    detail_data
):
    observations = []

    def add(
        source,
        content
    ):
        text = str(
            content
        ).strip()

        if text:
            observations.append({
                "observation_id":
                    f"O{len(observations) + 1}",

                "source":
                    source,

                "content":
                    text,
            })

    add(
        "rule_finding",
        confirmed_fact
    )

    for line in extract_section_lines(
        detail_data,
        "SYSTEMD PROPERTIES"
    ):
        add(
            "systemctl_show",
            line
        )

    for line in extract_section_lines(
        detail_data,
        "SYSTEMCTL STATUS"
    ):
        add(
            "systemctl_status",
            line
        )

    for line in extract_section_lines(
        detail_data,
        "SERVICE JOURNAL"
    ):
        add(
            "service_journal",
            line
        )

    return observations


def build_observation_map(
    observations
):
    return {
        item["observation_id"]:
            item
        for item in observations
    }