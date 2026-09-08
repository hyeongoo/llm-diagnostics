#!/usr/bin/env python3


def build_response_schema(
    finding_id,
    observation_ids
):
    ref = {
        "type": "string",
        "enum": observation_ids
    }

    return {
        "type": "object",

        "properties": {
            "finding_id": {
                "type": "string",
                "enum": [
                    finding_id
                ]
            },

            "selected_observations": {
                "type": "array",
                "items": ref
            },

            "failure_mechanism": {
                "type": "object",

                "properties": {
                    "identified": {
                        "type": "boolean"
                    },

                    "description": {
                        "type": "string"
                    },

                    "observation_refs": {
                        "type": "array",
                        "items": ref
                    },
                },

                "required": [
                    "identified",
                    "description",
                    "observation_refs"
                ],

                "additionalProperties":
                    False,
            },

            "cause_candidates": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "description": {
                            "type": "string"
                        },

                        "observation_refs": {
                            "type": "array",
                            "items": ref
                        },
                    },

                    "required": [
                        "description",
                        "observation_refs"
                    ],

                    "additionalProperties":
                        False,
                },
            },

            "checks": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "purpose": {
                            "type": "string"
                        },

                        "data_source": {
                            "type": "string"
                        },

                        "scope_detail": {
                            "type": "string"
                        },

                        "observation_refs": {
                            "type": "array",
                            "items": ref
                        },
                    },

                    "required": [
                        "purpose",
                        "data_source",
                        "scope_detail",
                        "observation_refs"
                    ],

                    "additionalProperties":
                        False,
                },
            },

            "remediation_candidates": {
                "type": "array",

                "items": {
                    "type": "object",

                    "properties": {
                        "action": {
                            "type": "string"
                        },

                        "rationale": {
                            "type": "string"
                        },

                        "caution": {
                            "type": "string"
                        },

                        "observation_refs": {
                            "type": "array",
                            "items": ref
                        },
                    },

                    "required": [
                        "action",
                        "rationale",
                        "caution",
                        "observation_refs"
                    ],

                    "additionalProperties":
                        False,
                },
            },
        },

        "required": [
            "finding_id",
            "selected_observations",
            "failure_mechanism",
            "cause_candidates",
            "checks",
            "remediation_candidates",
        ],

        "additionalProperties":
            False,
    }