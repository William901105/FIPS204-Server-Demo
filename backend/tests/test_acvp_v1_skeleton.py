from __future__ import annotations

import copy
import json
from typing import Any, Dict

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.main import app
from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    delete_acvp_v1_test_session,
    get_acvp_v1_algorithms,
    get_acvp_v1_test_session,
    get_acvp_v1_test_session_results,
    get_acvp_v1_test_session_vector_sets,
    get_acvp_v1_vector_set,
    get_acvp_v1_vector_set_expected_results,
    get_acvp_v1_vector_set_results,
    get_acvp_v1_version,
    list_acvp_v1_test_sessions,
    submit_acvp_v1_vector_set_results,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"

_raw_create_acvp_v1_test_session = create_acvp_v1_test_session
_raw_delete_acvp_v1_test_session = delete_acvp_v1_test_session
_raw_get_acvp_v1_algorithms = get_acvp_v1_algorithms
_raw_get_acvp_v1_test_session = get_acvp_v1_test_session
_raw_get_acvp_v1_test_session_results = get_acvp_v1_test_session_results
_raw_get_acvp_v1_test_session_vector_sets = get_acvp_v1_test_session_vector_sets
_raw_get_acvp_v1_vector_set = get_acvp_v1_vector_set
_raw_get_acvp_v1_vector_set_expected_results = get_acvp_v1_vector_set_expected_results
_raw_get_acvp_v1_vector_set_results = get_acvp_v1_vector_set_results
_raw_get_acvp_v1_version = get_acvp_v1_version
_raw_list_acvp_v1_test_sessions = list_acvp_v1_test_sessions
_raw_submit_acvp_v1_vector_set_results = submit_acvp_v1_vector_set_results


def create_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_create_acvp_v1_test_session(*args, **kwargs))


def delete_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_delete_acvp_v1_test_session(*args, **kwargs))


def get_acvp_v1_algorithms(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_algorithms(*args, **kwargs))


def get_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session(*args, **kwargs))


def get_acvp_v1_test_session_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session_results(*args, **kwargs))


def get_acvp_v1_test_session_vector_sets(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session_vector_sets(*args, **kwargs))


def get_acvp_v1_vector_set(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set(*args, **kwargs))


def get_acvp_v1_vector_set_expected_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set_expected_results(*args, **kwargs))


def get_acvp_v1_vector_set_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set_results(*args, **kwargs))


def get_acvp_v1_version(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_version(*args, **kwargs))


def list_acvp_v1_test_sessions(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_list_acvp_v1_test_sessions(*args, **kwargs))


def submit_acvp_v1_vector_set_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_submit_acvp_v1_vector_set_results(*args, **kwargs))


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_acvp_v1_routes_are_registered() -> None:
    paths = {route.path for route in app.routes}

    for path in (
        "/acvp/v1/version",
        "/acvp/v1/algorithms",
        "/acvp/v1/testSessions",
        "/acvp/v1/testSessions/{sessionId}",
        "/acvp/v1/testSessions/{sessionId}/vectorSets",
        "/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}",
        "/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results",
        "/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/expected",
        "/acvp/v1/vectorSets/{vectorSetId}",
        "/acvp/v1/vectorSets/{vectorSetId}/results",
        "/acvp/v1/vectorSets/{vectorSetId}/expectedResults",
        "/acvp/v1/testSessions/{sessionId}/results",
    ):
        assert path in paths


def test_version_and_algorithms_return_skeleton_metadata() -> None:
    version = get_acvp_v1_version()
    algorithms = get_acvp_v1_algorithms()

    assert version["apiVersion"] == "v1"
    assert_skeleton_metadata(version)

    entry = algorithms["algorithms"][0]
    assert entry["algorithm"] == "ML-DSA"
    assert entry["revision"] == "FIPS204"
    assert {"keyGen", "sigGen", "sigVer"}.issubset(set(entry["modes"]))
    assert_skeleton_metadata(algorithms)


def test_create_list_detail_vector_expected_submit_results_and_delete_flow() -> None:
    created = create_acvp_v1_test_session(
        {
            "prompt": keygen_prompt(),
            "label": "phase 3-2 keyGen skeleton",
            "autoGenerateExpectedResults": True,
        }
    )
    assert_skeleton_metadata(created)
    assert created["status"] == "vectorReady"
    assert created["vectorSetIds"]
    assert created["vectorSetUrls"]

    session_id = created["testSessionId"]
    vector_set_id = created["vectorSetIds"][0]

    listed = list_acvp_v1_test_sessions()
    assert_skeleton_metadata(listed)
    assert [item["testSessionId"] for item in listed["testSessions"]] == [session_id]
    assert "prompt" not in listed["testSessions"][0]
    assert "expectedResults" not in listed["testSessions"][0]

    detail = get_acvp_v1_test_session(session_id)
    assert_skeleton_metadata(detail)
    assert detail["testSessionId"] == session_id
    assert detail["vectorSets"][0]["vectorSetId"] == vector_set_id

    vector_sets = get_acvp_v1_test_session_vector_sets(session_id)
    assert_skeleton_metadata(vector_sets)
    assert vector_sets["vectorSets"][0]["vectorSetId"] == vector_set_id

    vector_set = get_acvp_v1_vector_set(vector_set_id)
    assert_skeleton_metadata(vector_set)
    assert vector_set["prompt"]["mode"] == "keyGen"

    expected = get_acvp_v1_vector_set_expected_results(vector_set_id)
    assert_skeleton_metadata(expected)
    assert expected["expectedResults"]["mode"] == "keyGen"

    submitted = submit_acvp_v1_vector_set_results(
        vector_set_id,
        {"response": expected["expectedResults"]},
    )
    assert_skeleton_metadata(submitted)
    assert submitted["status"] == "validated"
    assert submitted["validationResult"]["summary"]["failed"] == 0
    assert submitted["validationResult"]["summary"]["passed"] == 1

    vector_results = get_acvp_v1_vector_set_results(vector_set_id)
    assert_skeleton_metadata(vector_results)
    assert vector_results["validationResult"]["summary"]["passed"] == 1

    session_results = get_acvp_v1_test_session_results(session_id)
    assert_skeleton_metadata(session_results)
    assert session_results["summary"]["totalVectorSets"] == 1
    assert session_results["summary"]["passedVectorSets"] == 1

    deleted = delete_acvp_v1_test_session(session_id)
    assert_skeleton_metadata(deleted)
    assert deleted["cancelled"] is True
    assert deleted["status"] == "cancelled"

    after_delete = get_acvp_v1_test_session(session_id)
    assert_skeleton_metadata(after_delete)
    assert after_delete["status"] == "cancelled"


def test_submit_wrong_response_validates_failed() -> None:
    created = create_acvp_v1_test_session({"prompt": keygen_prompt()})
    vector_set_id = created["vectorSetIds"][0]
    expected = get_acvp_v1_vector_set_expected_results(vector_set_id)["expectedResults"]
    wrong_response = copy.deepcopy(expected)
    wrong_response["testGroups"][0]["tests"][0]["pk"] = flip_first_hex_char(
        wrong_response["testGroups"][0]["tests"][0]["pk"]
    )

    submitted = submit_acvp_v1_vector_set_results(
        vector_set_id,
        {"response": wrong_response},
    )

    assert_skeleton_metadata(submitted)
    assert submitted["status"] == "failed"
    assert submitted["validationResult"]["summary"]["failed"] == 1


def test_unknown_session_and_vector_set_return_skeleton_404() -> None:
    missing_session = get_acvp_v1_test_session("missing-session")
    missing_vector_set = get_acvp_v1_vector_set("missing-vector-set")

    assert_json_response(missing_session, 404)
    assert body_of(missing_session)["error"]["code"] == "UNKNOWN_TEST_SESSION"
    assert_skeleton_metadata(body_of(missing_session))

    assert_json_response(missing_vector_set, 404)
    assert body_of(missing_vector_set)["error"]["code"] == "UNKNOWN_VECTOR_SET"
    assert_skeleton_metadata(body_of(missing_vector_set))


def test_registration_payload_missing_required_fields_returns_skeleton_400() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [
                {
                    "algorithm": "ML-DSA",
                    "revision": "FIPS204",
                    "mode": "keyGen",
                }
            ]
        }
    )

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "missing_required_field"
    assert body["error"]["path"] == "$.algorithms[0].parameterSets"
    assert_skeleton_metadata(body)


def test_submit_before_vector_ready_returns_409() -> None:
    created = create_acvp_v1_test_session(
        {"prompt": keygen_prompt(), "autoGenerateExpectedResults": False}
    )
    vector_set_id = created["vectorSetIds"][0]

    response = submit_acvp_v1_vector_set_results(
        vector_set_id,
        {"response": {"vsId": 3101, "testGroups": []}},
    )

    assert_json_response(response, 409)
    body = body_of(response)
    assert body["error"]["code"] == "VECTOR_SET_NOT_READY"
    assert_skeleton_metadata(body)


def assert_skeleton_metadata(body: Dict[str, Any]) -> None:
    metadata = body.get("extensions", {}).get("localFips204Skeleton", body)
    assert metadata["productionReady"] is False
    assert metadata["profile"] == "local-fips204-skeleton"
    assert metadata["demoOnly"] is True
    assert metadata["notProductionAcvp"] is True


def assert_json_response(value: Any, status_code: int) -> None:
    assert isinstance(value, JSONResponse)
    assert value.status_code == status_code


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
        "vsId": 3101,
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


def flip_first_hex_char(value: str) -> str:
    first = "0" if value[0] != "0" else "1"
    return first + value[1:]
