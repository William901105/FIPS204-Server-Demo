from __future__ import annotations

import json
from typing import Any, Dict

from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    delete_acvp_v1_test_session,
    get_acvp_v1_test_session,
    get_acvp_v1_test_session_results,
    get_acvp_v1_vector_set,
    get_acvp_v1_vector_set_expected_results,
    get_acvp_v1_vector_set_results,
    submit_acvp_v1_vector_set_results,
)
from app.storage.sqlite_store import (
    get_acvp_session,
    get_acvp_vector_set,
    list_state_events,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"

_raw_create_acvp_v1_test_session = create_acvp_v1_test_session
_raw_delete_acvp_v1_test_session = delete_acvp_v1_test_session
_raw_get_acvp_v1_test_session = get_acvp_v1_test_session
_raw_get_acvp_v1_test_session_results = get_acvp_v1_test_session_results
_raw_get_acvp_v1_vector_set = get_acvp_v1_vector_set
_raw_get_acvp_v1_vector_set_expected_results = get_acvp_v1_vector_set_expected_results
_raw_get_acvp_v1_vector_set_results = get_acvp_v1_vector_set_results
_raw_submit_acvp_v1_vector_set_results = submit_acvp_v1_vector_set_results


def create_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_create_acvp_v1_test_session(*args, **kwargs))


def delete_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_delete_acvp_v1_test_session(*args, **kwargs))


def get_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session(*args, **kwargs))


def get_acvp_v1_test_session_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session_results(*args, **kwargs))


def get_acvp_v1_vector_set(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set(*args, **kwargs))


def get_acvp_v1_vector_set_expected_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set_expected_results(*args, **kwargs))


def get_acvp_v1_vector_set_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set_results(*args, **kwargs))


def submit_acvp_v1_vector_set_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_submit_acvp_v1_vector_set_results(*args, **kwargs))


def test_acvp_v1_session_vector_results_and_state_events_persist() -> None:
    created = body_of(
        create_acvp_v1_test_session(
            {
                "prompt": keygen_prompt(),
                "label": "sqlite acvp v1 persistence",
                "autoGenerateExpectedResults": True,
            }
        )
    )
    session_id = created["testSessionId"]
    vector_set_id = created["vectorSetIds"][0]

    vector_set = body_of(get_acvp_v1_vector_set(vector_set_id))
    expected = body_of(get_acvp_v1_vector_set_expected_results(vector_set_id))
    submitted = body_of(
        submit_acvp_v1_vector_set_results(
            vector_set_id,
            {"response": expected["expectedResults"]},
        )
    )
    vector_results = body_of(get_acvp_v1_vector_set_results(vector_set_id))
    session_results = body_of(get_acvp_v1_test_session_results(session_id))
    stored_session = get_acvp_session(session_id)
    stored_vector_set = get_acvp_vector_set(vector_set_id)
    session_events_before_delete = list_state_events("acvp_session", session_id)
    vector_events = list_state_events("acvp_vector_set", vector_set_id)
    deleted = body_of(delete_acvp_v1_test_session(session_id))
    session_after_delete = body_of(get_acvp_v1_test_session(session_id))
    session_events_after_delete = list_state_events("acvp_session", session_id)

    assert vector_set["prompt"]["mode"] == "keyGen"
    assert submitted["validationResult"]["summary"]["failed"] == 0
    assert vector_results["report"]["failedCount"] == 0
    assert session_results["summary"]["passedVectorSets"] == 1
    assert stored_session is not None
    assert stored_vector_set is not None
    assert stored_vector_set["response"] == expected["expectedResults"]
    assert stored_vector_set["validationResult"]["summary"]["passed"] == 1
    assert stored_vector_set["report"]["passedCount"] == 1
    assert "created" in [event["event"] for event in session_events_before_delete]
    assert "validated" in [event["event"] for event in session_events_before_delete]
    assert "validated" in [event["event"] for event in vector_events]
    assert deleted["status"] == "cancelled"
    assert session_after_delete["status"] == "cancelled"
    assert session_events_after_delete[-1]["event"] == "cancelled"


def body_of(value: Any) -> Dict[str, Any]:
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


def route_body(value: Any) -> Any:
    if isinstance(value, JSONResponse):
        return value
    return body_of(value)


def keygen_prompt() -> Dict[str, Any]:
    return {
        "vsId": 4103,
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
