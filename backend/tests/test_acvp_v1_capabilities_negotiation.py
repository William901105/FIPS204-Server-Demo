from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.capabilities import (
    SCHEMA_ACCEPTED_BUT_NOT_GENERATED_HASH_ALGS,
    is_registration_container,
    validate_registration_container,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.acvp_mldsa.errors import AcvpSchemaError
from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session,
    get_acvp_v1_test_session_results,
    get_acvp_v1_test_session_vector_sets,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_registration_container_parser_detects_algorithms_array() -> None:
    assert is_registration_container({"algorithms": [keygen_registration()]}) is True
    assert is_registration_container({"algorithms": "bad"}) is False
    assert is_registration_container({"prompt": keygen_prompt()}) is False

    normalized = validate_registration_container(
        {"algorithms": [keygen_registration()], "label": "keygen capabilities"}
    )

    assert normalized["label"] == "keygen capabilities"
    assert normalized["algorithms"][0]["mode"] == "keyGen"


def test_keygen_registration_accepted() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [keygen_registration()],
            "label": "keygen capabilities",
            "autoGenerateVectorSets": False,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "capabilitiesAccepted"
    assert response["vectorSetIds"] == []
    negotiated = response["negotiatedCapabilities"]["negotiated"][0]
    assert negotiated["mode"] == "keyGen"
    assert "ML-DSA-44" in negotiated["parameterSets"]
    assert "ML-DSA-65" in negotiated["parameterSets"]


def test_siggen_internal_external_registration_accepted() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [siggen_registration()],
            "label": "sigGen capabilities",
            "autoGenerateVectorSets": False,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "capabilitiesAccepted"
    assert response["vectorSetIds"] == []
    assert "Phase 3-5" in response["nextAction"]

    negotiated = response["negotiatedCapabilities"]["negotiated"][0]
    assert negotiated["mode"] == "sigGen"
    assert negotiated["deterministic"] == [True, False]
    assert "internal" in negotiated["signatureInterfaces"]
    assert "external" in negotiated["signatureInterfaces"]
    assert "SHA2-256" in negotiated["hashAlgs"]
    assert "SHA3-256" in negotiated["hashAlgs"]


def test_sigver_registration_accepted() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [sigver_registration()],
            "label": "sigVer capabilities",
            "autoGenerateVectorSets": False,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "capabilitiesAccepted"
    negotiated = response["negotiatedCapabilities"]["negotiated"][0]
    assert negotiated["mode"] == "sigVer"
    assert "deterministic" not in negotiated
    assert "internal" in negotiated["signatureInterfaces"]
    assert "external" in negotiated["signatureInterfaces"]


def test_multiple_algorithms_accepted() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [
                keygen_registration(),
                siggen_registration(),
                sigver_registration(),
            ],
            "label": "all modes",
            "autoGenerateVectorSets": False,
        }
    )

    assert_skeleton_metadata(response)
    negotiated = response["negotiatedCapabilities"]["negotiated"]
    assert [item["mode"] for item in negotiated] == ["keyGen", "sigGen", "sigVer"]


def test_unsupported_parameter_set_rejected_by_schema() -> None:
    registration = keygen_registration()
    registration["parameterSets"] = ["BAD-SET"]

    response = create_acvp_v1_test_session(
        {"algorithms": [registration], "autoGenerateVectorSets": False}
    )

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "invalid_parameter_set"
    assert body["error"]["path"] == "$.algorithms[0].parameterSets[0]"
    assert_skeleton_metadata(body)


def test_unsupported_algorithm_rejected_by_schema() -> None:
    registration = keygen_registration()
    registration["algorithm"] = "ECDSA"

    response = create_acvp_v1_test_session({"algorithms": [registration]})

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "unsupported_algorithm"
    assert body["error"]["path"] == "$.algorithms[0].algorithm"
    assert_skeleton_metadata(body)


def test_invalid_conditional_fields_rejected() -> None:
    external_with_external_mu = siggen_registration()
    external_with_external_mu["signatureInterfaces"] = ["external"]
    external_with_external_mu["externalMu"] = [True]

    internal_with_prehash = sigver_registration()
    internal_with_prehash["signatureInterfaces"] = ["internal"]
    internal_with_prehash["preHash"] = ["pure"]

    first = create_acvp_v1_test_session(
        {"algorithms": [external_with_external_mu]}
    )
    second = create_acvp_v1_test_session(
        {"algorithms": [internal_with_prehash]}
    )

    assert_json_response(first, 400)
    assert body_of(first)["error"]["code"] == "invalid_conditional_field"
    assert_skeleton_metadata(body_of(first))

    assert_json_response(second, 400)
    assert body_of(second)["error"]["code"] == "invalid_conditional_field"
    assert_skeleton_metadata(body_of(second))


def test_duplicate_algorithm_mode_revision_rejected() -> None:
    response = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration(), keygen_registration()]}
    )

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "duplicate_registration"
    assert body["error"]["path"] == "$.algorithms[1].mode"
    assert_skeleton_metadata(body)


def test_shake_hash_alg_is_warning_and_excluded_from_negotiated_hash_algs() -> None:
    registration = siggen_registration()
    registration["capabilities"][0]["hashAlgs"] = ["SHA2-256", "SHAKE-256"]

    response = create_acvp_v1_test_session({"algorithms": [registration]})

    assert_skeleton_metadata(response)
    assert "SHAKE-256" in SCHEMA_ACCEPTED_BUT_NOT_GENERATED_HASH_ALGS
    negotiated = response["negotiatedCapabilities"]["negotiated"][0]
    assert negotiated["hashAlgs"] == ["SHA2-256"]
    assert response["negotiationWarnings"]
    assert response["negotiationWarnings"][0]["value"] == "SHAKE-256"
    assert "not generated" in response["negotiationWarnings"][0]["reason"]


def test_registration_with_only_unsupported_generation_capabilities_returns_400() -> None:
    registration = siggen_registration()
    registration["signatureInterfaces"] = ["external"]
    registration["preHash"] = ["preHash"]
    registration.pop("externalMu")
    registration["capabilities"][0]["hashAlgs"] = ["SHAKE-256"]

    response = create_acvp_v1_test_session({"algorithms": [registration]})

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "UNSUPPORTED_CAPABILITIES"
    assert body["error"]["path"] == "$.algorithms"
    assert_skeleton_metadata(body)


def test_prompt_based_phase_3_2_flow_still_works() -> None:
    response = create_acvp_v1_test_session(
        {
            "prompt": keygen_prompt(),
            "label": "phase 3-2 prompt regression",
            "autoGenerateExpectedResults": True,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "vectorReady"
    assert len(response["vectorSetIds"]) == 1


def test_capabilities_only_session_vector_sets_endpoint_returns_empty_list() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [siggen_registration()], "autoGenerateVectorSets": False}
    )
    session_id = created["testSessionId"]

    detail = get_acvp_v1_test_session(session_id)
    vector_sets = get_acvp_v1_test_session_vector_sets(session_id)

    assert_skeleton_metadata(detail)
    assert detail["status"] == "capabilitiesAccepted"
    assert detail["negotiatedCapabilities"]["negotiated"][0]["mode"] == "sigGen"
    assert detail["vectorSetCount"] == 0
    assert detail["vectorSetIds"] == []

    assert_skeleton_metadata(vector_sets)
    assert vector_sets["vectorSets"] == []
    assert "Phase 3-5" in vector_sets["nextAction"]


def test_capabilities_only_session_results_returns_409_before_vector_generation() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [sigver_registration()], "autoGenerateVectorSets": False}
    )
    response = get_acvp_v1_test_session_results(created["testSessionId"])

    assert_json_response(response, 409)
    body = body_of(response)
    assert body["error"]["code"] == "VECTOR_SETS_NOT_GENERATED"
    assert "Generate vector sets" in body["error"]["message"]
    assert_skeleton_metadata(body)


def test_prompt_and_algorithms_cannot_both_be_present() -> None:
    response = create_acvp_v1_test_session(
        {
            "prompt": keygen_prompt(),
            "algorithms": [keygen_registration()],
        }
    )

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert_skeleton_metadata(body)


def test_registration_container_validation_rewrites_paths() -> None:
    registration = keygen_registration()
    registration["parameterSets"] = ["BAD-SET"]

    with pytest.raises(AcvpSchemaError) as exc_info:
        validate_registration_container({"algorithms": [registration]})

    assert exc_info.value.path == "$.algorithms[0].parameterSets[0]"


def assert_skeleton_metadata(body: Dict[str, Any]) -> None:
    assert body["productionReady"] is False
    assert body["profile"] == "local-fips204-skeleton"
    assert body["demoOnly"] is True
    assert body["notProductionAcvp"] is True


def assert_json_response(value: Any, status_code: int) -> None:
    assert isinstance(value, JSONResponse)
    assert value.status_code == status_code


def body_of(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        return json.loads(value.body.decode("utf-8"))
    return value


def keygen_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": ["ML-DSA-44", "ML-DSA-65"],
    }


def siggen_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "sigGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "deterministic": [True, False],
        "signatureInterfaces": ["internal", "external"],
        "externalMu": [True, False],
        "preHash": ["pure", "preHash"],
        "capabilities": [capability()],
    }


def sigver_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "sigVer",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "signatureInterfaces": ["internal", "external"],
        "externalMu": [True, False],
        "preHash": ["pure", "preHash"],
        "capabilities": [capability()],
    }


def capability() -> Dict[str, List[Any]]:
    return {
        "parameterSets": ["ML-DSA-44"],
        "messageLength": [{"min": 8, "max": 4096, "increment": 8}],
        "contextLength": [{"min": 0, "max": 2040, "increment": 8}],
        "hashAlgs": ["SHA2-256", "SHA3-256"],
    }


def keygen_prompt() -> Dict[str, Any]:
    return {
        "vsId": 3301,
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
