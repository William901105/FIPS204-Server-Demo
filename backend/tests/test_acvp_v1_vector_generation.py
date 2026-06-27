from __future__ import annotations

import copy
import json
from typing import Any, Dict, List

from fastapi.responses import JSONResponse

from app.acvp_mldsa.expected import generate_expected_results_from_prompt
from app.acvp_mldsa.validators import validate_mldsa_response, validate_mldsa_vector_set
from app.acvp_protocol.capabilities import (
    negotiate_mldsa_capabilities,
    validate_registration_container,
)
from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    generate_acvp_v1_test_session_vector_sets,
    get_acvp_v1_test_session_vector_sets,
    get_acvp_v1_vector_set,
    get_acvp_v1_vector_set_expected_results,
    submit_acvp_v1_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.acvp_protocol.vector_generation import (
    derive_hex,
    generate_vector_sets_from_negotiated_capabilities,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
OTHER_CAMPAIGN_SEED = "ABCDEF00112233445566778899AABBCC"


def setup_function() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_derive_hex_is_deterministic_and_label_sensitive() -> None:
    first = derive_hex("seed", "label", 32)
    second = derive_hex("seed", "label", 32)
    different = derive_hex("seed", "other-label", 32)

    assert first == second
    assert first != different
    assert len(first) == 64
    assert first == first.upper()


def test_keygen_vector_generation() -> None:
    vector_sets = generate_vector_sets_from_negotiated_capabilities(
        negotiated_for([keygen_registration(["ML-DSA-44", "ML-DSA-65"])]),
        campaign_seed=CAMPAIGN_SEED,
        tests_per_group=2,
    )

    prompt = vector_sets[0]
    validate_mldsa_vector_set(prompt)
    expected = generate_expected_results_from_prompt(prompt)
    validate_mldsa_response(expected, expected_mode="keyGen")

    assert prompt["mode"] == "keyGen"
    assert [group["parameterSet"] for group in prompt["testGroups"]] == [
        "ML-DSA-44",
        "ML-DSA-65",
    ]
    assert all(len(test["seed"]) == 64 for group in prompt["testGroups"] for test in group["tests"])


def test_siggen_internal_deterministic_vector_generation() -> None:
    prompt = generate_vector_sets_from_negotiated_capabilities(
        negotiated_for([siggen_registration(["internal"], [False], [True])]),
        campaign_seed=CAMPAIGN_SEED,
        tests_per_group=1,
    )[0]

    validate_mldsa_vector_set(prompt)
    expected = generate_expected_results_from_prompt(prompt)
    validate_mldsa_response(expected, expected_mode="sigGen")
    group = prompt["testGroups"][0]
    test = group["tests"][0]

    assert group["deterministic"] is True
    assert group["signatureInterface"] == "internal"
    assert group["externalMu"] is False
    assert "sk" in test and "message" in test
    assert "rnd" not in test


def test_siggen_randomized_vector_generation_includes_rnd() -> None:
    prompt = generate_vector_sets_from_negotiated_capabilities(
        negotiated_for([siggen_registration(["internal"], [False], [False])]),
        campaign_seed=CAMPAIGN_SEED,
        tests_per_group=1,
    )[0]
    test = prompt["testGroups"][0]["tests"][0]

    validate_mldsa_vector_set(prompt)
    assert len(test["rnd"]) == 64
    generate_expected_results_from_prompt(prompt)


def test_siggen_external_pure_and_prehash_generation() -> None:
    prompt = generate_vector_sets_from_negotiated_capabilities(
        negotiated_for([siggen_registration(["external"], deterministic=[True])]),
        campaign_seed=CAMPAIGN_SEED,
        tests_per_group=1,
    )[0]

    validate_mldsa_vector_set(prompt)
    generate_expected_results_from_prompt(prompt)
    pure_group = next(group for group in prompt["testGroups"] if group["preHash"] == "pure")
    prehash_group = next(group for group in prompt["testGroups"] if group["preHash"] == "preHash")

    assert "message" in pure_group["tests"][0]
    assert "context" in pure_group["tests"][0]
    assert "hashAlg" not in pure_group["tests"][0]
    assert prehash_group["tests"][0]["hashAlg"] == "SHA2-256"


def test_sigver_vector_generation_has_true_and_false_expected_results() -> None:
    prompt = generate_vector_sets_from_negotiated_capabilities(
        negotiated_for([sigver_registration(["internal"], [False])]),
        campaign_seed=CAMPAIGN_SEED,
        tests_per_group=2,
    )[0]
    expected = generate_expected_results_from_prompt(prompt)
    results = [
        test["testPassed"]
        for group in expected["testGroups"]
        for test in group["tests"]
    ]

    validate_mldsa_vector_set(prompt)
    validate_mldsa_response(expected, expected_mode="sigVer")
    assert True in results
    assert False in results


def test_registration_auto_generates_vector_sets() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": full_registration(),
            "campaignSeed": CAMPAIGN_SEED,
            "testsPerGroup": 1,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "vectorReady"
    assert len(response["vectorSetIds"]) == 3
    assert response["vectorGeneration"]["generatedVectorSetCount"] == 3
    assert response["vectorGeneration"]["modes"] == ["keyGen", "sigGen", "sigVer"]


def test_auto_generate_vector_sets_false_preserves_capabilities_accepted() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [keygen_registration()],
            "campaignSeed": CAMPAIGN_SEED,
            "autoGenerateVectorSets": False,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "capabilitiesAccepted"
    assert response["vectorSetIds"] == []
    assert "Phase 3-5" in response["nextAction"]


def test_explicit_generate_endpoint() -> None:
    created = create_acvp_v1_test_session(
        {
            "algorithms": [keygen_registration()],
            "campaignSeed": OTHER_CAMPAIGN_SEED,
            "testsPerGroup": 2,
            "autoGenerateVectorSets": False,
        }
    )
    generated = generate_acvp_v1_test_session_vector_sets(
        created["testSessionId"],
        {"campaignSeed": OTHER_CAMPAIGN_SEED, "testsPerGroup": 2},
    )

    assert_skeleton_metadata(generated)
    assert generated["status"] == "vectorReady"
    assert len(generated["vectorSetIds"]) == 1
    assert generated["vectorGeneration"]["testsPerGroup"] == 2


def test_generated_vector_and_expected_results_download() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
    )
    vector_set_id = created["vectorSetIds"][0]

    vector = get_acvp_v1_vector_set(vector_set_id)
    expected = get_acvp_v1_vector_set_expected_results(vector_set_id)

    assert_skeleton_metadata(vector)
    assert_skeleton_metadata(expected)
    assert vector["prompt"]["mode"] == "keyGen"
    assert expected["expectedResults"]["mode"] == "keyGen"


def test_generated_vector_sets_list_endpoint_has_metadata() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
    )
    listed = get_acvp_v1_test_session_vector_sets(created["testSessionId"])

    assert_skeleton_metadata(listed)
    assert len(listed["vectorSets"]) == 1
    assert listed["vectorSets"][0]["status"] == "ready"
    assert listed["vectorSets"][0]["generatedFromCapabilities"] is True


def test_submit_matching_expected_results_passes() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
    )
    vector_set_id = created["vectorSetIds"][0]
    expected = get_acvp_v1_vector_set_expected_results(vector_set_id)["expectedResults"]

    submitted = submit_acvp_v1_vector_set_results(
        vector_set_id,
        {"response": expected},
    )

    assert_skeleton_metadata(submitted)
    assert submitted["validationResult"]["summary"]["failed"] == 0
    assert submitted["validationResult"]["summary"]["missing"] == 0
    assert submitted["validationResult"]["summary"]["malformed"] == 0
    assert submitted["validationResult"]["summary"].get("extra", 0) == 0


def test_submit_wrong_response_fails() -> None:
    created = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
    )
    vector_set_id = created["vectorSetIds"][0]
    wrong = copy.deepcopy(get_acvp_v1_vector_set_expected_results(vector_set_id)["expectedResults"])
    wrong["testGroups"][0]["tests"][0]["pk"] = mutate_hex(wrong["testGroups"][0]["tests"][0]["pk"])

    submitted = submit_acvp_v1_vector_set_results(
        vector_set_id,
        {"response": wrong},
    )

    assert_skeleton_metadata(submitted)
    assert submitted["validationResult"]["summary"]["failed"] > 0


def test_same_campaign_seed_reproduces_prompt_contents() -> None:
    first = create_acvp_v1_test_session(
        {"algorithms": full_registration(), "campaignSeed": CAMPAIGN_SEED, "testsPerGroup": 1}
    )
    first_prompts = prompts_for(first)
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()
    second = create_acvp_v1_test_session(
        {"algorithms": full_registration(), "campaignSeed": CAMPAIGN_SEED, "testsPerGroup": 1}
    )

    assert first_prompts == prompts_for(second)


def test_different_campaign_seed_changes_vector_data() -> None:
    first = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": CAMPAIGN_SEED}
    )
    first_prompt = prompts_for(first)[0]
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()
    second = create_acvp_v1_test_session(
        {"algorithms": [keygen_registration()], "campaignSeed": OTHER_CAMPAIGN_SEED}
    )

    assert first_prompt != prompts_for(second)[0]


def test_shake_is_not_generated_when_supported_hash_remains() -> None:
    registration = siggen_registration(["external"], deterministic=[True])
    registration["capabilities"][0]["hashAlgs"] = ["SHA2-256", "SHAKE-256"]
    response = create_acvp_v1_test_session(
        {"algorithms": [registration], "campaignSeed": CAMPAIGN_SEED}
    )
    prompt = prompts_for(response)[0]

    assert response["negotiationWarnings"][0]["value"] == "SHAKE-256"
    assert all(
        test.get("hashAlg") != "SHAKE-256"
        for group in prompt["testGroups"]
        for test in group["tests"]
    )


def test_only_shake_prehash_returns_400() -> None:
    registration = siggen_registration(["external"], deterministic=[True])
    registration["preHash"] = ["preHash"]
    registration["capabilities"][0]["hashAlgs"] = ["SHAKE-256"]

    response = create_acvp_v1_test_session({"algorithms": [registration]})

    assert_json_response(response, 400)
    body = body_of(response)
    assert body["error"]["code"] == "UNSUPPORTED_CAPABILITIES"
    assert_skeleton_metadata(body)


def test_prompt_based_phase_3_2_flow_still_works() -> None:
    response = create_acvp_v1_test_session(
        {
            "prompt": keygen_prompt(),
            "label": "prompt regression",
            "autoGenerateExpectedResults": True,
        }
    )

    assert_skeleton_metadata(response)
    assert response["status"] == "vectorReady"
    assert len(response["vectorSetIds"]) == 1


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


def negotiated_for(algorithms: List[Dict[str, Any]]) -> Dict[str, Any]:
    return negotiate_mldsa_capabilities(validate_registration_container({"algorithms": algorithms}))


def prompts_for(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        get_acvp_v1_vector_set(vector_set_id)["prompt"]
        for vector_set_id in response["vectorSetIds"]
    ]


def full_registration() -> List[Dict[str, Any]]:
    return [
        keygen_registration(),
        siggen_registration(["internal", "external"]),
        sigver_registration(["internal", "external"]),
    ]


def keygen_registration(parameter_sets: List[str] = None) -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": parameter_sets or ["ML-DSA-44"],
    }


def siggen_registration(
    signature_interfaces: List[str],
    external_mu: List[bool] = None,
    deterministic: List[bool] = None,
) -> Dict[str, Any]:
    registration: Dict[str, Any] = {
        "algorithm": "ML-DSA",
        "mode": "sigGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "deterministic": deterministic or [True, False],
        "signatureInterfaces": signature_interfaces,
        "capabilities": [capability()],
    }
    if "internal" in signature_interfaces:
        registration["externalMu"] = external_mu if external_mu is not None else [False, True]
    if "external" in signature_interfaces:
        registration["preHash"] = ["pure", "preHash"]
    return registration


def sigver_registration(
    signature_interfaces: List[str],
    external_mu: List[bool] = None,
) -> Dict[str, Any]:
    registration: Dict[str, Any] = {
        "algorithm": "ML-DSA",
        "mode": "sigVer",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "signatureInterfaces": signature_interfaces,
        "capabilities": [capability()],
    }
    if "internal" in signature_interfaces:
        registration["externalMu"] = external_mu if external_mu is not None else [False, True]
    if "external" in signature_interfaces:
        registration["preHash"] = ["pure", "preHash"]
    return registration


def capability() -> Dict[str, List[Any]]:
    return {
        "parameterSets": ["ML-DSA-44"],
        "messageLength": [{"min": 8, "max": 128, "increment": 8}],
        "contextLength": [{"min": 0, "max": 64, "increment": 8}],
        "hashAlgs": ["SHA2-256"],
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


def mutate_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]
