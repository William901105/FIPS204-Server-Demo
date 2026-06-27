from __future__ import annotations

import copy
import json
from typing import Any, Dict, Tuple

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    delete_acvp_v1_test_session_vector_set,
    get_acvp_v1_test_session_vector_set,
    get_acvp_v1_test_session_vector_set_expected,
    get_acvp_v1_test_session_vector_set_results,
    get_acvp_v1_vector_set,
    submit_acvp_v1_test_session_vector_set_results,
    update_acvp_v1_test_session_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.storage.sqlite_store import get_acvp_vector_set, list_state_events


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_nested_vector_set_download_expected_submit_and_get_results() -> None:
    session_id, vector_set_id = create_session()

    vector = envelope_body(get_acvp_v1_test_session_vector_set(session_id, vector_set_id))
    expected = envelope_body(
        get_acvp_v1_test_session_vector_set_expected(session_id, vector_set_id)
    )
    submitted = envelope_body(
        submit_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            {"response": expected["expectedResults"]},
        )
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )

    assert vector["prompt"]["mode"] == "keyGen"
    assert expected["expectedResults"]["mode"] == "keyGen"
    assert expected["localSkeletonExpectedEndpoint"] is True
    assert submitted["validationResult"]["summary"]["failed"] == 0
    assert submitted["validationResult"]["summary"]["passed"] == 1
    assert results["validationResult"]["summary"]["passed"] == 1
    assert "productionReady" not in submitted
    assert submitted["extensions"]["localFips204Skeleton"]["productionReady"] is False


def test_nested_vector_set_wrong_session_returns_404_envelope() -> None:
    _, vector_set_id = create_session()

    response = get_acvp_v1_test_session_vector_set("not-the-session", vector_set_id)

    assert isinstance(response, JSONResponse)
    assert response.status_code == 404
    body = envelope_body(response)
    assert body["error"]["code"] == "UNKNOWN_TEST_SESSION"


def test_nested_put_results_replaces_previous_submission() -> None:
    session_id, vector_set_id = create_session()
    expected = envelope_body(
        get_acvp_v1_test_session_vector_set_expected(session_id, vector_set_id)
    )["expectedResults"]
    wrong = copy.deepcopy(expected)
    wrong["testGroups"][0]["tests"][0]["pk"] = mutate_hex(
        wrong["testGroups"][0]["tests"][0]["pk"]
    )

    failed = envelope_body(
        submit_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            {"response": wrong},
        )
    )
    updated = envelope_body(
        update_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            {"response": expected},
        )
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )

    assert failed["validationResult"]["summary"]["failed"] == 1
    assert updated["submissionAction"] == "updated"
    assert updated["localSkeletonPutReplaceBehavior"] is True
    assert updated["validationResult"]["summary"]["failed"] == 0
    assert results["validationResult"]["summary"]["passed"] == 1


def test_nested_delete_cancels_vector_set_and_blocks_submit() -> None:
    session_id, vector_set_id = create_session()
    expected = envelope_body(
        get_acvp_v1_test_session_vector_set_expected(session_id, vector_set_id)
    )["expectedResults"]

    cancelled = envelope_body(
        delete_acvp_v1_test_session_vector_set(session_id, vector_set_id)
    )
    blocked = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": expected},
    )
    stored = get_acvp_vector_set(vector_set_id)
    events = list_state_events("acvp_vector_set", vector_set_id)

    assert cancelled["cancelled"] is True
    assert cancelled["status"] == "cancelled"
    assert stored is not None
    assert stored["status"] == "cancelled"
    assert "cancelled" in [event["event"] for event in events]
    assert isinstance(blocked, JSONResponse)
    assert blocked.status_code == 409
    assert envelope_body(blocked)["error"]["code"] in {
        "TEST_SESSION_CANCELLED",
        "VECTOR_SET_CANCELLED",
    }


def test_flat_vector_set_route_remains_local_compatibility_alias() -> None:
    _, vector_set_id = create_session()

    flat = get_acvp_v1_vector_set(vector_set_id)

    assert isinstance(flat, dict)
    assert flat["localCompatibilityAlias"] is True
    assert flat["prompt"]["mode"] == "keyGen"
    assert flat["productionReady"] is False


def create_session() -> Tuple[str, str]:
    created = envelope_body(
        create_acvp_v1_test_session(
            {
                "prompt": keygen_prompt(),
                "label": "phase 4-3 nested route test",
                "autoGenerateExpectedResults": True,
            }
        )
    )
    return created["testSessionId"], created["vectorSetIds"][0]


def envelope_body(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        value = json.loads(value.body.decode("utf-8"))
    assert isinstance(value, list)
    assert value[0] == {"acvVersion": "1.0"}
    assert isinstance(value[1], dict)
    return value[1]


def keygen_prompt() -> Dict[str, Any]:
    return {
        "vsId": 43101,
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "tests": [{"tcId": 1, "seed": SEED_32_BYTES}],
            }
        ],
    }


def mutate_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]
