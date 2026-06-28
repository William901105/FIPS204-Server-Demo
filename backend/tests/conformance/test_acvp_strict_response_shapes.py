from __future__ import annotations

import json
from typing import Any, Dict

from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    generate_acvp_v1_test_session_vector_sets,
    get_acvp_v1_test_session_results,
    get_acvp_v1_test_session_vector_set,
    get_acvp_v1_vector_set,
    get_acvp_v1_vector_set_expected_results,
    get_acvp_v1_vector_set_results,
    list_acvp_v1_test_sessions,
    submit_acvp_v1_test_session,
    submit_acvp_v1_test_session_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)


CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
LOCAL_FIELDS = {
    "prompt",
    "vectorSetId",
    "testSessionId",
    "status",
    "stateHistory",
    "productionReady",
    "demoOnly",
    "notProductionAcvp",
    "campaignSeed",
    "generationProfile",
}


def setup_function() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_strict_vector_set_download_is_algorithm_payload_without_local_fields() -> None:
    session_id, vector_set_id = _create_strict_session()
    vector = _body(
        get_acvp_v1_test_session_vector_set(
            session_id,
            vector_set_id,
            workflowProfile="strict",
        )
    )

    assert {"vsId", "algorithm", "mode", "revision", "testGroups"}.issubset(vector)
    assert vector["isSample"] is False
    assert LOCAL_FIELDS.isdisjoint(vector)


def test_strict_test_session_results_are_protocol_summary() -> None:
    session_id, vector_set_id = _create_strict_session()
    expected = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["expectedResults"]
    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": expected},
        workflowProfile="strict",
    )
    results = _body(get_acvp_v1_test_session_results(session_id, workflowProfile="strict"))

    assert results["passed"] is True
    assert results["results"][0]["vectorSetUrl"].endswith(f"/vectorSets/{vector_set_id}")
    assert results["results"][0]["status"] == "passed"
    assert "summary" not in results
    assert "stateHistory" not in results
    assert "validationResult" not in results
    assert "report" not in results


def test_strict_flat_aliases_are_disabled() -> None:
    _session_id, vector_set_id = _create_strict_session()

    for response in (
        get_acvp_v1_vector_set(vector_set_id, workflowProfile="strict"),
        get_acvp_v1_vector_set_expected_results(vector_set_id, workflowProfile="strict"),
        get_acvp_v1_vector_set_results(vector_set_id, workflowProfile="strict"),
    ):
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        body = _body(response)
        assert body["error"]["code"] == "LOCAL_COMPATIBILITY_ALIAS_DISABLED"


def test_strict_local_helper_routes_are_disabled() -> None:
    created = _body(
        create_acvp_v1_test_session(
            {
                "algorithms": [_keygen_registration()],
                "campaignSeed": CAMPAIGN_SEED,
                "autoGenerateVectorSets": False,
            },
            workflowProfile="strict",
        )
    )

    generate_response = generate_acvp_v1_test_session_vector_sets(
        created["testSessionId"],
        {},
        workflowProfile="strict",
    )
    submit_response = submit_acvp_v1_test_session(
        created["testSessionId"],
        {},
        workflowProfile="strict",
    )

    assert isinstance(generate_response, JSONResponse)
    assert generate_response.status_code == 409
    assert _body(generate_response)["error"]["code"] == "LOCAL_HELPER_ROUTE_DISABLED"
    assert isinstance(submit_response, JSONResponse)
    assert submit_response.status_code == 409
    assert _body(submit_response)["error"]["code"] == "LOCAL_HELPER_ROUTE_DISABLED"


def test_strict_paging_uses_prev_not_previous() -> None:
    for index in range(3):
        create_acvp_v1_test_session(
            {
                "algorithms": [_keygen_registration()],
                "campaignSeed": CAMPAIGN_SEED,
                "label": f"strict page {index}",
            },
            workflowProfile="strict",
        )

    page = _body(
        list_acvp_v1_test_sessions(
            limit="1",
            offset="1",
            workflowProfile="strict",
        )
    )

    assert "prev" in page["links"]
    assert "previous" not in page["links"]
    assert page["links"]["prev"] is not None


def _create_strict_session() -> tuple[str, str]:
    created = _body(
        create_acvp_v1_test_session(
            {"algorithms": [_keygen_registration()], "campaignSeed": CAMPAIGN_SEED},
            workflowProfile="strict",
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

