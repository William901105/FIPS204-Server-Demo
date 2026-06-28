from __future__ import annotations

import json
from typing import Any, Dict

from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set_expected,
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


def test_strict_sample_expected_endpoint_returns_payload_direct() -> None:
    session_id, vector_set_id = _create_strict_session(is_sample=True)
    expected = _body(
        get_acvp_v1_test_session_vector_set_expected(
            session_id,
            vector_set_id,
            workflowProfile="strict",
        )
    )

    assert expected["algorithm"] == "ML-DSA"
    assert expected["mode"] == "keyGen"
    assert expected["isSample"] is True
    assert "expectedResults" not in expected


def test_strict_non_sample_expected_endpoint_is_denied() -> None:
    session_id, vector_set_id = _create_strict_session()

    response = get_acvp_v1_test_session_vector_set_expected(
        session_id,
        vector_set_id,
        workflowProfile="strict",
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 403
    body = _body(response)
    assert body["error"]["code"] == "EXPECTED_RESULTS_NOT_AVAILABLE_FOR_NON_SAMPLE"


def test_strict_non_sample_still_validates_with_hidden_expected_results() -> None:
    session_id, vector_set_id = _create_strict_session()
    expected = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["expectedResults"]

    response = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": expected},
        workflowProfile="strict",
    )

    assert response.status_code == 204
    stored = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]
    assert stored["response"] == expected
    assert stored["validationResult"]["summary"]["failed"] == 0


def test_local_expected_endpoint_keeps_wrapper() -> None:
    session_id, vector_set_id = _create_local_session()
    expected = _body(get_acvp_v1_test_session_vector_set_expected(session_id, vector_set_id))

    assert expected["expectedResults"]["mode"] == "keyGen"
    assert expected["localSkeletonExpectedEndpoint"] is True


def _create_strict_session(*, is_sample: bool = False) -> tuple[str, str]:
    payload: Dict[str, Any] = {
        "algorithms": [_keygen_registration()],
        "campaignSeed": CAMPAIGN_SEED,
    }
    if is_sample:
        payload["isSample"] = True
    created = _body(create_acvp_v1_test_session(payload, workflowProfile="strict"))
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

