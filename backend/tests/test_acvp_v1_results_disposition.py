from __future__ import annotations

import copy
import json
from typing import Any, Dict, Tuple

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.disposition import build_acvp_vector_set_results
from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set_expected,
    get_acvp_v1_test_session_vector_set_results,
    get_acvp_v1_vector_set_results,
    submit_acvp_v1_test_session_vector_set_results,
    submit_acvp_v1_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
OTHER_SEED_32_BYTES = "101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F"


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_disposition_adapter_maps_all_pass_to_passed() -> None:
    session_id, vector_set_id, expected = create_session()

    submitted = envelope_body(
        submit_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            {"response": expected},
        )
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )

    assert submitted["results"]["vsId"] == expected["vsId"]
    assert submitted["results"]["disposition"] == "passed"
    assert all(test["result"] == "passed" for test in submitted["results"]["tests"])
    assert all("expected" not in test for test in submitted["results"]["tests"])
    assert results["results"] == submitted["results"]


def test_disposition_adapter_maps_wrong_value_to_fail() -> None:
    session_id, vector_set_id, expected = create_session()
    wrong = copy.deepcopy(expected)
    wrong["testGroups"][0]["tests"][0]["pk"] = mutate_hex(
        wrong["testGroups"][0]["tests"][0]["pk"]
    )

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": wrong},
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )["results"]

    assert results["disposition"] == "fail"
    failing = [test for test in results["tests"] if test["result"] == "fail"]
    assert failing
    assert failing[0]["reason"]


def test_disposition_adapter_maps_missing_response_case_to_missing() -> None:
    session_id, vector_set_id, expected = create_session(test_count=2)
    missing = copy.deepcopy(expected)
    missing["testGroups"][0]["tests"] = missing["testGroups"][0]["tests"][:1]

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": missing},
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )["results"]

    assert results["disposition"] == "missing"
    missing_tests = [test for test in results["tests"] if test["result"] == "missing"]
    assert missing_tests
    assert missing_tests[0]["reason"] == "response test case is missing"


def test_disposition_adapter_maps_extra_response_case_to_fail() -> None:
    session_id, vector_set_id, expected = create_session()
    extra = copy.deepcopy(expected)
    extra_test = copy.deepcopy(extra["testGroups"][0]["tests"][0])
    extra_test["tcId"] = 999
    extra["testGroups"][0]["tests"].append(extra_test)

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": extra},
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )["results"]

    assert results["disposition"] == "fail"
    extra_results = [
        test for test in results["tests"]
        if test["tcId"] == 999 and test["result"] == "fail"
    ]
    assert extra_results
    assert extra_results[0]["reason"] == "extra response test case"


def test_nist_style_envelope_submission_is_accepted() -> None:
    session_id, vector_set_id, expected = create_session()
    body = copy.deepcopy(expected)
    body["showExpected"] = False

    submit = envelope_body(
        submit_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            [{"acvVersion": "1.0"}, body],
        )
    )

    assert submit["results"]["disposition"] == "passed"
    assert "validationResult" not in submit


def test_invalid_nist_style_envelope_is_rejected_with_envelope_error() -> None:
    session_id, vector_set_id, expected = create_session()

    response = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        [{"wrong": "1.0"}, expected],
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = envelope_body(response)
    assert body["error"]["code"] == "INVALID_ACVP_ENVELOPE"


def test_flat_results_compatibility_alias_keeps_local_fields() -> None:
    _, vector_set_id, expected = create_session()

    submitted = submit_acvp_v1_vector_set_results(
        vector_set_id,
        {"response": expected},
    )
    results = get_acvp_v1_vector_set_results(vector_set_id)

    assert submitted["localCompatibilityAlias"] is True
    assert submitted["validationResult"]["summary"]["failed"] == 0
    assert submitted["acvpResults"]["results"]["disposition"] == "passed"
    assert results["localCompatibilityAlias"] is True
    assert results["validationResult"]["summary"]["passed"] == 1


def test_disposition_builds_unreceived_results_before_submission() -> None:
    _, _, expected = create_session()
    vector_set = {
        "vectorSetId": "vector-1",
        "testSessionId": "session-1",
        "status": "ready",
        "vsId": expected["vsId"],
        "expectedResults": expected,
        "prompt": keygen_prompt(),
    }

    results = build_acvp_vector_set_results(
        vector_set=vector_set,
        validation_result=None,
        response=None,
        expected_results=expected,
    )["results"]

    assert results["disposition"] == "unreceived"
    assert results["tests"][0]["result"] == "unreceived"


def create_session(test_count: int = 1) -> Tuple[str, str, Dict[str, Any]]:
    created = envelope_body(
        create_acvp_v1_test_session(
            {
                "prompt": keygen_prompt(test_count=test_count),
                "label": "phase 4-3 commit2 disposition test",
                "autoGenerateExpectedResults": True,
            }
        )
    )
    session_id = created["testSessionId"]
    vector_set_id = created["vectorSetIds"][0]
    expected = envelope_body(
        get_acvp_v1_test_session_vector_set_expected(session_id, vector_set_id)
    )["expectedResults"]
    return session_id, vector_set_id, expected


def envelope_body(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        value = json.loads(value.body.decode("utf-8"))
    assert isinstance(value, list)
    assert value[0] == {"acvVersion": "1.0"}
    assert isinstance(value[1], dict)
    return value[1]


def keygen_prompt(test_count: int = 1) -> Dict[str, Any]:
    seeds = [SEED_32_BYTES, OTHER_SEED_32_BYTES]
    return {
        "vsId": 43201,
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "tests": [
                    {"tcId": tc_id + 1, "seed": seeds[tc_id]}
                    for tc_id in range(test_count)
                ],
            }
        ],
    }


def mutate_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]
