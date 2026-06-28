from __future__ import annotations

import copy
import json
from typing import Any, Dict, Tuple

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set_expected,
    get_acvp_v1_test_session_vector_set_results,
    submit_acvp_v1_test_session_vector_set_results,
    update_acvp_v1_test_session_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.storage.sqlite_store import get_acvp_vector_set


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_show_expected_false_hides_expected_and_provided() -> None:
    session_id, vector_set_id, expected = create_session()
    wrong = wrong_response(expected)

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": wrong, "showExpected": False},
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )["results"]
    failing = first_failing_test(results)

    assert results["disposition"] == "fail"
    assert "expected" not in failing
    assert "provided" not in failing


def test_show_expected_true_includes_expected_and_provided_from_acvp_envelope() -> None:
    session_id, vector_set_id, expected = create_session()
    wrong = wrong_response(expected)
    wrong["showExpected"] = True

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        [{"acvVersion": "1.0"}, wrong],
    )
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )["results"]
    failing = first_failing_test(results)

    assert results["disposition"] == "fail"
    assert failing["expected"] == expected["testGroups"][0]["tests"][0]
    assert failing["provided"] == wrong["testGroups"][0]["tests"][0]


def test_put_updates_show_expected_visibility() -> None:
    session_id, vector_set_id, expected = create_session()
    wrong = wrong_response(expected)

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        {"response": wrong, "showExpected": False},
    )
    hidden = first_failing_test(
        envelope_body(
            get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
        )["results"]
    )

    wrong_with_expected = copy.deepcopy(wrong)
    wrong_with_expected["showExpected"] = True
    update = envelope_body(
        update_acvp_v1_test_session_vector_set_results(
            session_id,
            vector_set_id,
            [{"acvVersion": "1.0"}, wrong_with_expected],
        )
    )
    shown = first_failing_test(
        envelope_body(
            get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
        )["results"]
    )

    assert "expected" not in hidden
    assert update["extensions"]["localFips204Skeleton"]["localPutReplaceBehavior"] is True
    assert update["extensions"]["localFips204Skeleton"]["showExpected"] is True
    assert "expected" in shown
    assert "provided" in shown


def test_show_expected_and_acvp_results_persist_in_sqlite() -> None:
    session_id, vector_set_id, expected = create_session()
    wrong = wrong_response(expected)
    wrong["showExpected"] = True

    submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        [{"acvVersion": "1.0"}, wrong],
    )
    stored = get_acvp_vector_set(vector_set_id)
    results = envelope_body(
        get_acvp_v1_test_session_vector_set_results(session_id, vector_set_id)
    )["results"]

    assert stored is not None
    assert stored["showExpected"] is True
    assert stored["acvpResults"]["results"]["disposition"] == "fail"
    assert first_failing_test(results)["expected"] == expected["testGroups"][0]["tests"][0]


def create_session() -> Tuple[str, str, Dict[str, Any]]:
    created = envelope_body(
        create_acvp_v1_test_session(
            {
                "prompt": keygen_prompt(),
                "label": "phase 4-3 commit2 showExpected test",
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


def wrong_response(expected: Dict[str, Any]) -> Dict[str, Any]:
    wrong = copy.deepcopy(expected)
    pk = wrong["testGroups"][0]["tests"][0]["pk"]
    wrong["testGroups"][0]["tests"][0]["pk"] = mutate_hex(pk)
    return wrong


def first_failing_test(results: Dict[str, Any]) -> Dict[str, Any]:
    return next(test for test in results["tests"] if test["result"] == "fail")


def keygen_prompt() -> Dict[str, Any]:
    return {
        "vsId": 43202,
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
