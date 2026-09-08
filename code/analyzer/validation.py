#!/usr/bin/env python3

import sys


def valid_refs(
    value,
    observation_map
):
    if not isinstance(
        value,
        list
    ):
        return []

    refs = []

    for item in value:
        ref = str(
            item
        ).strip()

        if (
            ref in observation_map
            and ref not in refs
        ):
            refs.append(
                ref
            )

    return refs


def validate_response(
    raw,
    finding_id,
    observation_map
):
    """
    Python은 의미를 판단하지 않고
    구조와 Observation 참조만 확인한다.
    """

    if (
        raw.get(
            "finding_id"
        )
        != finding_id
    ):
        print(
            "Unexpected finding_id "
            "from LLM: "
            f"{raw.get('finding_id')}"
        )
        sys.exit(1)

    result = {
        "selected_observations":
            valid_refs(
                raw.get(
                    "selected_observations",
                    []
                ),
                observation_map
            ),

        "failure_mechanism":
            None,

        "cause_candidates":
            [],

        "checks":
            [],

        "remediation_candidates":
            [],
    }

    mechanism = raw.get(
        "failure_mechanism",
        {}
    )

    if (
        isinstance(
            mechanism,
            dict
        )
        and mechanism.get(
            "identified"
        ) is True
    ):
        description = str(
            mechanism.get(
                "description",
                ""
            )
        ).strip()

        refs = valid_refs(
            mechanism.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            description
            and refs
        ):
            result[
                "failure_mechanism"
            ] = {
                "description":
                    description,

                "observation_refs":
                    refs,
            }

    for item in raw.get(
        "cause_candidates",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        description = str(
            item.get(
                "description",
                ""
            )
        ).strip()

        refs = valid_refs(
            item.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            description
            and refs
        ):
            result[
                "cause_candidates"
            ].append({
                "description":
                    description,

                "observation_refs":
                    refs,
            })

    for item in raw.get(
        "checks",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        purpose = str(
            item.get(
                "purpose",
                ""
            )
        ).strip()

        data_source = str(
            item.get(
                "data_source",
                ""
            )
        ).strip()

        scope_detail = str(
            item.get(
                "scope_detail",
                ""
            )
        ).strip()

        refs = valid_refs(
            item.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            purpose
            and data_source
            and scope_detail
            and refs
        ):
            result[
                "checks"
            ].append({
                "purpose":
                    purpose,

                "data_source":
                    data_source,

                "scope_detail":
                    scope_detail,

                "observation_refs":
                    refs,
            })

    for item in raw.get(
        "remediation_candidates",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        action = str(
            item.get(
                "action",
                ""
            )
        ).strip()

        rationale = str(
            item.get(
                "rationale",
                ""
            )
        ).strip()

        caution = str(
            item.get(
                "caution",
                ""
            )
        ).strip()

        refs = valid_refs(
            item.get(
                "observation_refs",
                []
            ),
            observation_map
        )

        if (
            action
            and rationale
            and caution
            and refs
        ):
            result[
                "remediation_candidates"
            ].append({
                "action":
                    action,

                "rationale":
                    rationale,

                "caution":
                    caution,

                "observation_refs":
                    refs,
            })

    return result