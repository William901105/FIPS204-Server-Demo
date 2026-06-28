from __future__ import annotations

import copy
import json
from typing import Any, Dict

from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set_results,
    submit_acvp_v1_test_session_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)


CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"


def setup_function() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_strict_results_before_submit_are_unreceived() -> None:
    session_id, vector_set_id = _create_strict_session()
    results = _body(
        get_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            workflowProfile="strict",
        )
    )

    assert results["results"]["disposition"] == "unreceived"


def test_strict_post_results_returns_204_and_get_results_passed() -> None:
    session_id, vector_set_id = _create_strict_session()
    expected = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["expectedResults"]

    response = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": expected},
        workflowProfile="strict",
    )
    results = _body(
        get_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            workflowProfile="strict",
        )
    )

    assert response.status_code == 204
    assert ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["response"] == expected
    assert ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["validationResult"] is not None
    assert results["results"]["disposition"] == "passed"
    assert all("expected" not in test for test in results["results"]["tests"])


def test_strict_wrong_response_is_accepted_then_reports_fail() -> None:
    session_id, vector_set_id = _create_strict_session()
    wrong = copy.deepcopy(ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["expectedResults"])
    wrong["testGroups"][0]["tests"][0]["pk"] = _mutate_hex(
        wrong["testGroups"][0]["tests"][0]["pk"]
    )

    response = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": wrong},
        workflowProfile="strict",
    )
    results = _body(
        get_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            workflowProfile="strict",
        )
    )

    assert response.status_code == 204
    assert results["results"]["disposition"] == "fail"


def test_strict_malformed_response_returns_400() -> None:
    session_id, vector_set_id = _create_strict_session()

    response = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": {"bad": True}},
        workflowProfile="strict",
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400


def test_local_post_results_still_returns_validation_body() -> None:
    session_id, vector_set_id = _create_local_session()
    expected = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["expectedResults"]

    response = _body(
        submit_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            {"response": expected},
        )
    )

    assert response["results"]["disposition"] == "passed"
    assert response["extensions"]["localFips204Skeleton"]["validationResult"] is not None


def _create_strict_session() -> tuple[str, str]:
    created = _body(
        create_acvp_v1_test_session(
            {"algorithms": [_keygen_registration()], "campaignSeed": CAMPAIGN_SEED},
            workflowProfile="strict",
        )
    )
    return created["testSessionId"], created["vectorSetIds"][0]


def _create_local_session() -> tuple[str, str]:
    created = _body(
        create_acvp_v1_test_session(
            {"algorithms": [_keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
        )
    )
    return created["testSessionId"], created["vectorSetIds"][0]


def _keygen_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": ["ML-DSA-44"],
    }


def _mutate_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]


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

