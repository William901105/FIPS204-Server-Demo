from __future__ import annotations

import copy
import json
from typing import Any, Dict, List

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    delete_acvp_v1_test_session,
    delete_acvp_v1_vector_set,
    generate_acvp_v1_test_session_vector_sets,
    get_acvp_v1_test_session,
    get_acvp_v1_test_session_results,
    get_acvp_v1_vector_set,
    get_acvp_v1_vector_set_expected_results,
    submit_acvp_v1_test_session,
    submit_acvp_v1_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.acvp_protocol.state_machine import (
    StateTransitionError,
    TestSessionStatus as SessionStatus,
    VectorSetStatus,
    now_timestamp,
    transition_session,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"

_raw_create_acvp_v1_test_session = create_acvp_v1_test_session
_raw_delete_acvp_v1_test_session = delete_acvp_v1_test_session
_raw_delete_acvp_v1_vector_set = delete_acvp_v1_vector_set
_raw_generate_acvp_v1_test_session_vector_sets = generate_acvp_v1_test_session_vector_sets
_raw_get_acvp_v1_test_session = get_acvp_v1_test_session
_raw_get_acvp_v1_test_session_results = get_acvp_v1_test_session_results
_raw_get_acvp_v1_vector_set = get_acvp_v1_vector_set
_raw_get_acvp_v1_vector_set_expected_results = get_acvp_v1_vector_set_expected_results
_raw_submit_acvp_v1_test_session = submit_acvp_v1_test_session
_raw_submit_acvp_v1_vector_set_results = submit_acvp_v1_vector_set_results


def create_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_create_acvp_v1_test_session(*args, **kwargs))


def delete_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_delete_acvp_v1_test_session(*args, **kwargs))


def delete_acvp_v1_vector_set(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_delete_acvp_v1_vector_set(*args, **kwargs))


def generate_acvp_v1_test_session_vector_sets(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_generate_acvp_v1_test_session_vector_sets(*args, **kwargs))


def get_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session(*args, **kwargs))


def get_acvp_v1_test_session_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_test_session_results(*args, **kwargs))


def get_acvp_v1_vector_set(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set(*args, **kwargs))


def get_acvp_v1_vector_set_expected_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_get_acvp_v1_vector_set_expected_results(*args, **kwargs))


def submit_acvp_v1_test_session(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_submit_acvp_v1_test_session(*args, **kwargs))


def submit_acvp_v1_vector_set_results(*args: Any, **kwargs: Any) -> Any:
    return route_body(_raw_submit_acvp_v1_vector_set_results(*args, **kwargs))


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_state_transition_helpers_accept_and_reject_transitions() -> None:
    session = {
        "testSessionId": "session-1",
        "status": SessionStatus.CREATED.value,
        "updatedAt": now_timestamp(),
    }

    transition_session(
        session,
        SessionStatus.CAPABILITIES_ACCEPTED.value,
        reason="accepted for test",
    )

    assert session["status"] == SessionStatus.CAPABILITIES_ACCEPTED.value
    with pytest.raises(StateTransitionError):
        transition_session(
            session,
            SessionStatus.CREATED.value,
            reason="cannot go backwards",
        )

    cancelled = {
        "testSessionId": "session-2",
        "status": SessionStatus.CANCELLED.value,
        "updatedAt": now_timestamp(),
    }
    with pytest.raises(StateTransitionError):
        transition_session(
            cancelled,
            SessionStatus.VECTOR_READY.value,
            reason="cancelled is terminal",
        )


def test_prompt_based_create_sets_state_history() -> None:
    created = create_acvp_v1_test_session(
        {"prompt": keygen_prompt(), "autoGenerateExpectedResults": True}
    )
    vector_set_id = created["vectorSetIds"][0]
    vector_set = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]

    assert_skeleton_metadata(created)
    assert created["status"] == SessionStatus.VECTOR_READY.value
    assert vector_set["status"] == VectorSetStatus.READY.value
    assert created["stateHistory"]
    assert vector_set["stateHistory"]
    assert_state_event_shape(created["stateHistory"][0])
    assert_state_event_shape(vector_set["stateHistory"][0])


def test_registration_auto_vector_generation_records_state_history() -> None:
    created = create_acvp_v1_test_session(
        {
            "algorithms": full_registration(),
            "campaignSeed": CAMPAIGN_SEED,
            "testsPerGroup": 1,
            "autoGenerateVectorSets": True,
        }
    )
    session = ACVP_SKELETON_SESSION_STORE[created["testSessionId"]]

    assert_skeleton_metadata(created)
    assert created["status"] == SessionStatus.VECTOR_READY.value
    assert len(created["vectorSetIds"]) == 3
    assert all(
        ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["status"] == VectorSetStatus.READY.value
        for vector_set_id in created["vectorSetIds"]
    )
    events = [event["event"] for event in session["stateHistory"]]
    assert "capabilitiesAccepted" in events
    assert "vectorReady" in events
    assert "vectorGenerated" in events


def test_vector_download_marks_vector_and_session_downloaded() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": full_registration(), "campaignSeed": CAMPAIGN_SEED, "testsPerGroup": 1}
    )

    for vector_set_id in created["vectorSetIds"]:
        vector = get_acvp_v1_vector_set(vector_set_id)
        assert_skeleton_metadata(vector)
        assert vector["status"] == VectorSetStatus.DOWNLOADED.value
        assert vector["downloadedAt"]

    session = get_acvp_v1_test_session(created["testSessionId"])
    assert session["status"] == SessionStatus.VECTOR_DOWNLOADED.value


def test_submit_matching_response_transitions_to_validated() -> None:
    created = create_acvp_v1_test_session({"prompt": keygen_prompt()})
    vector_set_id = created["vectorSetIds"][0]
    expected = get_acvp_v1_vector_set_expected_results(vector_set_id)["expectedResults"]

    submitted = submit_acvp_v1_vector_set_results(vector_set_id, {"response": expected})
    session = get_acvp_v1_test_session(created["testSessionId"])

    assert submitted["status"] == VectorSetStatus.VALIDATED.value
    assert session["status"] == SessionStatus.VALIDATED.value
    assert_history_contains(submitted["stateHistory"], ["resultsSubmitted", "validating", "validated"])


def test_submit_wrong_response_transitions_to_failed() -> None:
    created = create_acvp_v1_test_session({"prompt": keygen_prompt()})
    vector_set_id = created["vectorSetIds"][0]
    wrong = copy.deepcopy(get_acvp_v1_vector_set_expected_results(vector_set_id)["expectedResults"])
    wrong["testGroups"][0]["tests"][0]["pk"] = mutate_hex(wrong["testGroups"][0]["tests"][0]["pk"])

    submitted = submit_acvp_v1_vector_set_results(vector_set_id, {"response": wrong})
    session = get_acvp_v1_test_session(created["testSessionId"])

    assert submitted["status"] == VectorSetStatus.FAILED.value
    assert session["status"] == SessionStatus.FAILED.value


def test_partial_submissions_keep_session_results_submitted() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": full_registration(), "campaignSeed": CAMPAIGN_SEED, "testsPerGroup": 1}
    )
    first_vector_set_id = created["vectorSetIds"][0]
    expected = get_acvp_v1_vector_set_expected_results(first_vector_set_id)["expectedResults"]

    submit_acvp_v1_vector_set_results(first_vector_set_id, {"response": expected})
    session = get_acvp_v1_test_session(created["testSessionId"])
    results = get_acvp_v1_test_session_results(created["testSessionId"])

    assert session["status"] == SessionStatus.RESULTS_SUBMITTED.value
    assert results["summary"]["submittedVectorSets"] == 1
    assert results["summary"]["pendingVectorSets"] == 2


def test_session_submit_endpoint_all_pass_any_fail_and_incomplete() -> None:
    passing = create_acvp_v1_test_session({"prompt": keygen_prompt()})
    passing_vector_id = passing["vectorSetIds"][0]
    expected = get_acvp_v1_vector_set_expected_results(passing_vector_id)["expectedResults"]
    submit_acvp_v1_vector_set_results(passing_vector_id, {"response": expected})

    passed = submit_acvp_v1_test_session(passing["testSessionId"])
    assert passed["status"] == SessionStatus.VALIDATED.value
    assert passed["summary"]["sessionPassed"] is True

    failing = create_acvp_v1_test_session({"prompt": keygen_prompt(vs_id=3502)})
    failing_vector_id = failing["vectorSetIds"][0]
    wrong = copy.deepcopy(get_acvp_v1_vector_set_expected_results(failing_vector_id)["expectedResults"])
    wrong["testGroups"][0]["tests"][0]["pk"] = mutate_hex(wrong["testGroups"][0]["tests"][0]["pk"])
    submit_acvp_v1_vector_set_results(failing_vector_id, {"response": wrong})

    failed = submit_acvp_v1_test_session(failing["testSessionId"])
    assert failed["status"] == SessionStatus.FAILED.value
    assert failed["summary"]["sessionPassed"] is False

    incomplete = create_acvp_v1_test_session(
        {"algorithms": full_registration(), "campaignSeed": CAMPAIGN_SEED, "testsPerGroup": 1}
    )
    first_vector_set_id = incomplete["vectorSetIds"][0]
    first_expected = get_acvp_v1_vector_set_expected_results(first_vector_set_id)["expectedResults"]
    submit_acvp_v1_vector_set_results(first_vector_set_id, {"response": first_expected})

    response = submit_acvp_v1_test_session(incomplete["testSessionId"])
    assert_json_response(response, 409)
    assert body_of(response)["error"]["code"] == "VECTOR_SET_RESULTS_INCOMPLETE"


def test_capabilities_accepted_without_vectors_cannot_submit() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "autoGenerateVectorSets": False}
    )

    response = submit_acvp_v1_test_session(created["testSessionId"])

    assert_json_response(response, 409)
    assert body_of(response)["error"]["code"] == "VECTOR_SETS_NOT_GENERATED"


def test_generate_endpoint_invalid_states() -> None:
    created = create_acvp_v1_test_session(
        {
            "algorithms": [keygen_registration()],
            "autoGenerateVectorSets": False,
            "campaignSeed": CAMPAIGN_SEED,
        }
    )
    generated = generate_acvp_v1_test_session_vector_sets(created["testSessionId"], {})
    assert generated["status"] == SessionStatus.VECTOR_READY.value

    duplicate = generate_acvp_v1_test_session_vector_sets(created["testSessionId"], {})
    assert_json_response(duplicate, 409)
    assert body_of(duplicate)["error"]["code"] == "VECTOR_SETS_ALREADY_GENERATED"

    prompt_based = create_acvp_v1_test_session({"prompt": keygen_prompt(vs_id=3503)})
    prompt_generate = generate_acvp_v1_test_session_vector_sets(prompt_based["testSessionId"], {})
    assert_json_response(prompt_generate, 409)
    assert body_of(prompt_generate)["error"]["code"] == "NEGOTIATED_CAPABILITIES_NOT_AVAILABLE"

    cancellable = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "autoGenerateVectorSets": False}
    )
    delete_acvp_v1_test_session(cancellable["testSessionId"])
    cancelled_generate = generate_acvp_v1_test_session_vector_sets(cancellable["testSessionId"], {})
    assert_json_response(cancelled_generate, 409)
    assert body_of(cancelled_generate)["error"]["code"] == "TEST_SESSION_CANCELLED"


def test_soft_cancel_session_keeps_session_and_blocks_submit() -> None:
    created = create_acvp_v1_test_session({"prompt": keygen_prompt()})
    vector_set_id = created["vectorSetIds"][0]

    cancelled = delete_acvp_v1_test_session(created["testSessionId"])
    detail = get_acvp_v1_test_session(created["testSessionId"])
    expected = get_acvp_v1_vector_set_expected_results(vector_set_id)
    submit = submit_acvp_v1_vector_set_results(vector_set_id, {"response": keygen_prompt()})

    assert cancelled["cancelled"] is True
    assert detail["status"] == SessionStatus.CANCELLED.value
    assert detail["vectorSets"][0]["status"] == VectorSetStatus.CANCELLED.value
    assert_json_response(expected, 409)
    assert_json_response(submit, 409)
    assert body_of(submit)["error"]["code"] == "TEST_SESSION_CANCELLED"


def test_cancel_vector_set_cancels_single_vector_session() -> None:
    created = create_acvp_v1_test_session({"prompt": keygen_prompt()})
    vector_set_id = created["vectorSetIds"][0]

    cancelled = delete_acvp_v1_vector_set(vector_set_id)
    submit = submit_acvp_v1_vector_set_results(vector_set_id, {"response": keygen_prompt()})
    session = get_acvp_v1_test_session(created["testSessionId"])

    assert cancelled["cancelled"] is True
    assert cancelled["status"] == VectorSetStatus.CANCELLED.value
    assert session["status"] == SessionStatus.CANCELLED.value
    assert_json_response(submit, 409)
    assert body_of(submit)["error"]["code"] == "TEST_SESSION_CANCELLED"


def test_expiration_marks_session_and_vector_sets_expired() -> None:
    created = create_acvp_v1_test_session(
        {"prompt": keygen_prompt(), "expiresInSeconds": 0}
    )
    vector_set_id = created["vectorSetIds"][0]

    expired = get_acvp_v1_vector_set(vector_set_id)
    detail = get_acvp_v1_test_session(created["testSessionId"])
    submit = submit_acvp_v1_vector_set_results(vector_set_id, {"response": keygen_prompt()})

    assert_json_response(expired, 409)
    assert body_of(expired)["error"]["code"] == "TEST_SESSION_EXPIRED"
    assert detail["status"] == SessionStatus.EXPIRED.value
    assert detail["vectorSets"][0]["status"] == VectorSetStatus.EXPIRED.value
    assert_json_response(submit, 409)


def test_phase_3_regressions_and_skeleton_metadata() -> None:
    generated = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
    )
    assert_skeleton_metadata(generated)
    assert generated["status"] == SessionStatus.VECTOR_READY.value

    expected = get_acvp_v1_vector_set_expected_results(generated["vectorSetIds"][0])
    submitted = submit_acvp_v1_vector_set_results(
        generated["vectorSetIds"][0],
        {"response": expected["expectedResults"]},
    )
    assert_skeleton_metadata(expected)
    assert_skeleton_metadata(submitted)
    assert submitted["status"] == VectorSetStatus.VALIDATED.value

    capabilities_only = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "autoGenerateVectorSets": False}
    )
    assert capabilities_only["status"] == SessionStatus.CAPABILITIES_ACCEPTED.value
    assert capabilities_only["vectorSetIds"] == []

    prompt_based = create_acvp_v1_test_session(
        {"prompt": keygen_prompt(vs_id=3504), "autoGenerateExpectedResults": True}
    )
    assert_skeleton_metadata(prompt_based)
    assert prompt_based["status"] == SessionStatus.VECTOR_READY.value


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


def assert_state_event_shape(event: Dict[str, Any]) -> None:
    assert {"at", "event", "from", "to", "reason"}.issubset(event)


def assert_history_contains(state_history: List[Dict[str, Any]], events: List[str]) -> None:
    actual = [event["event"] for event in state_history]
    for event in events:
        assert event in actual


def keygen_prompt(vs_id: int = 3501) -> Dict[str, Any]:
    return {
        "vsId": vs_id,
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


def full_registration() -> List[Dict[str, Any]]:
    return [
        keygen_registration(),
        siggen_registration(["internal", "external"]),
        sigver_registration(["internal", "external"]),
    ]


def keygen_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": ["ML-DSA-44"],
    }


def siggen_registration(signature_interfaces: List[str]) -> Dict[str, Any]:
    registration: Dict[str, Any] = {
        "algorithm": "ML-DSA",
        "mode": "sigGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "deterministic": [True],
        "signatureInterfaces": signature_interfaces,
        "capabilities": [capability()],
    }
    if "internal" in signature_interfaces:
        registration["externalMu"] = [False]
    if "external" in signature_interfaces:
        registration["preHash"] = ["pure"]
    return registration


def sigver_registration(signature_interfaces: List[str]) -> Dict[str, Any]:
    registration: Dict[str, Any] = {
        "algorithm": "ML-DSA",
        "mode": "sigVer",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "signatureInterfaces": signature_interfaces,
        "capabilities": [capability()],
    }
    if "internal" in signature_interfaces:
        registration["externalMu"] = [False]
    if "external" in signature_interfaces:
        registration["preHash"] = ["pure"]
    return registration


def capability() -> Dict[str, List[Any]]:
    return {
        "parameterSets": ["ML-DSA-44"],
        "messageLength": [{"min": 8, "max": 128, "increment": 8}],
        "contextLength": [{"min": 0, "max": 64, "increment": 8}],
        "hashAlgs": ["SHA2-256"],
    }


def mutate_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]
