from __future__ import annotations

import json
from typing import Any, Dict, List

from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set,
    get_acvp_v1_version,
    get_acvp_v1_vector_set,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)


CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"


def setup_function() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_default_local_workflow_preserves_vector_set_wrapper() -> None:
    created = _body(
        create_acvp_v1_test_session(
            {"algorithms": [_keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
        )
    )
    vector = _body(get_acvp_v1_vector_set(created["vectorSetIds"][0]))

    assert "prompt" in vector
    assert vector["prompt"]["isSample"] is True
    assert vector["localCompatibilityAlias"] is True


def test_strict_workflow_can_be_enabled_by_query() -> None:
    created = _body(
        create_acvp_v1_test_session(
            {"algorithms": [_keygen_registration()], "campaignSeed": CAMPAIGN_SEED},
            workflowProfile="strict",
        )
    )
    vector = _body(
        get_acvp_v1_test_session_vector_set(
            created["testSessionId"],
            created["vectorSetIds"][0],
            workflowProfile="strict",
        )
    )

    assert vector["algorithm"] == "ML-DSA"
    assert vector["mode"] == "keyGen"
    assert vector["isSample"] is False
    assert "prompt" not in vector


def test_invalid_workflow_profile_returns_400() -> None:
    response = get_acvp_v1_version(workflowProfile="bad")

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _body(response)
    assert body["error"]["code"] == "INVALID_WORKFLOW_PROFILE"
    assert body["error"]["path"] == "$.workflowProfile"


def test_generation_profile_and_workflow_profile_are_distinct() -> None:
    created = _body(
        create_acvp_v1_test_session(
            {
                "algorithms": [_keygen_registration()],
                "campaignSeed": CAMPAIGN_SEED,
                "generationProfile": "nist-conformance",
                "testsPerGroup": 1,
            },
            workflowProfile="strict",
        )
    )
    prompt = ACVP_SKELETON_VECTOR_SET_STORE[created["vectorSetIds"][0]]["prompt"]

    assert created["generationProfile"] == "nist-conformance"
    assert prompt["isSample"] is False
    assert len(prompt["testGroups"][0]["tests"]) >= 25


def _keygen_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": ["ML-DSA-44"],
    }


def _body(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        value = json.loads(value.body.decode("utf-8"))
    if (
        isinstance(value, list)
        and len(value) >= 2
        and isinstance(value[0], dict)
        and value[0].get("acvVersion") == "1.0"
    ):
        return value[1]
    return value
