from __future__ import annotations

import copy
import json
from collections import Counter
from itertools import cycle, islice
from typing import Any, Dict, List

from fastapi.responses import JSONResponse

from app.acvp_mldsa.expected import generate_expected_results_from_prompt
from app.acvp_mldsa.validators import validate_mldsa_response, validate_mldsa_vector_set
from app.acvp_protocol.capabilities import (
    negotiate_mldsa_capabilities,
    validate_registration_container,
)
from app.acvp_protocol.routes import create_acvp_v1_test_session
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.acvp_protocol.vector_generation import (
    LOCAL_DEBUG_PROFILE,
    MAX_TESTS_PER_GROUP,
    NIST_CONFORMANCE_PROFILE,
    NIST_KEYGEN_TESTS_PER_GROUP,
    NIST_SIGGEN_REJECTION_OUTCOME_TESTS,
    NIST_SIGGEN_TESTS_PER_GROUP,
    NIST_SIGGEN_TOTAL_REJECTION_TESTS,
    NIST_SIGVER_TESTS_PER_GROUP,
    SIGGEN_REJECTION_OUTCOME_KATS,
    SIGGEN_TOTAL_REJECTION_KATS,
    SIGVER_CONFORMANCE_MODIFICATION_SEQUENCE,
    SIGVER_MODIFICATION_CLASSES,
    generate_vector_sets_from_negotiated_capabilities,
)
from app.validator import validate


CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def setup_function() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_local_debug_profile_keeps_small_vector_sets() -> None:
    prompt = _generate([_keygen_registration(["ML-DSA-44"])], tests_per_group=2)[0]

    assert prompt["mode"] == "keyGen"
    assert prompt["testGroups"][0]["parameterSet"] == "ML-DSA-44"
    assert len(prompt["testGroups"][0]["tests"]) == 2


def test_nist_conformance_profile_is_not_capped_by_local_debug_max() -> None:
    response = _route_body(
        create_acvp_v1_test_session(
            {
                "algorithms": [_keygen_registration(["ML-DSA-44"])],
                "campaignSeed": CAMPAIGN_SEED,
                "testsPerGroup": MAX_TESTS_PER_GROUP + 1,
                "generationProfile": NIST_CONFORMANCE_PROFILE,
            }
        )
    )

    assert response["status"] == "vectorReady"
    assert response["vectorGeneration"]["generationProfile"] == NIST_CONFORMANCE_PROFILE
    vector_set_id = response["vectorSetIds"][0]
    prompt = ACVP_SKELETON_VECTOR_SET_STORE[vector_set_id]["prompt"]
    assert len(prompt["testGroups"][0]["tests"]) == NIST_KEYGEN_TESTS_PER_GROUP


def test_unknown_generation_profile_returns_normalized_400() -> None:
    response = create_acvp_v1_test_session(
        {
            "algorithms": [_keygen_registration(["ML-DSA-44"])],
            "generationProfile": "unknown-profile",
        }
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = _body_of(response)
    assert body["error"]["code"] == "invalid_value"
    assert body["error"]["path"] == "$.generationProfile"


def test_nist_conformance_keygen_counts_and_seed_shape() -> None:
    prompt = _generate(
        [_keygen_registration(PARAMETER_SETS)],
        tests_per_group=1,
        generation_profile=NIST_CONFORMANCE_PROFILE,
    )[0]

    validate_mldsa_vector_set(prompt)
    expected = generate_expected_results_from_prompt(prompt)
    validate_mldsa_response(expected, expected_mode="keyGen")

    assert [group["parameterSet"] for group in prompt["testGroups"]] == PARAMETER_SETS
    assert all(
        len(group["tests"]) >= NIST_KEYGEN_TESTS_PER_GROUP
        for group in prompt["testGroups"]
    )
    assert all(
        len(test["seed"]) == 64
        for group in prompt["testGroups"]
        for test in group["tests"]
    )
    assert _unique_tc_ids(prompt)


def test_nist_conformance_siggen_counts_and_capability_coverage() -> None:
    prompt = _generate(
        [_siggen_registration(["internal", "external"], PARAMETER_SETS)],
        tests_per_group=1,
        generation_profile=NIST_CONFORMANCE_PROFILE,
    )[0]

    validate_mldsa_vector_set(prompt)
    groups = prompt["testGroups"]

    assert {group["parameterSet"] for group in groups} == set(PARAMETER_SETS)
    assert {group["signatureInterface"] for group in groups} == {"internal", "external"}
    assert {group["deterministic"] for group in groups} == {True, False}
    assert {group.get("externalMu") for group in groups if group["signatureInterface"] == "internal"} == {False, True}
    assert {group.get("preHash") for group in groups if group["signatureInterface"] == "external"} == {"pure", "preHash"}
    assert all(len(group["tests"]) >= NIST_SIGGEN_TESTS_PER_GROUP for group in groups)
    assert all(
        "rnd" not in test
        for group in groups
        if group["deterministic"] is True
        for test in group["tests"]
    )
    assert all(
        "rnd" in test and len(test["rnd"]) == 64
        for group in groups
        if group["deterministic"] is False
        for test in group["tests"]
    )
    assert _hash_algs_in_prompt(prompt) == {"SHA2-256", "SHA3-256"}


def test_nist_conformance_siggen_rejection_kat_inclusion() -> None:
    """This verifies NIST KAT inclusion, not runtime rejection-count instrumentation."""
    prompt = _generate(
        [_siggen_registration(["internal"], PARAMETER_SETS)],
        tests_per_group=1,
        generation_profile=NIST_CONFORMANCE_PROFILE,
    )[0]

    for parameter_set in PARAMETER_SETS:
        group = next(
            group
            for group in prompt["testGroups"]
            if group["parameterSet"] == parameter_set
            and group["signatureInterface"] == "internal"
            and group["deterministic"] is True
            and group["externalMu"] is False
        )
        messages = Counter(test["message"] for test in group["tests"])

        outcome_messages = [
            kat["message"]
            for kat in _minimum_kats(
                SIGGEN_REJECTION_OUTCOME_KATS,
                parameter_set,
                NIST_SIGGEN_REJECTION_OUTCOME_TESTS,
            )
        ]
        total_messages = [
            kat["message"]
            for kat in _minimum_kats(
                SIGGEN_TOTAL_REJECTION_KATS,
                parameter_set,
                NIST_SIGGEN_TOTAL_REJECTION_TESTS,
            )
        ]

        assert len(group["tests"]) >= (
            NIST_SIGGEN_TESTS_PER_GROUP
            + NIST_SIGGEN_REJECTION_OUTCOME_TESTS
            + NIST_SIGGEN_TOTAL_REJECTION_TESTS
        )
        assert sum(messages[message] for message in outcome_messages) >= NIST_SIGGEN_REJECTION_OUTCOME_TESTS
        assert sum(messages[message] for message in total_messages) >= NIST_SIGGEN_TOTAL_REJECTION_TESTS

    expected = generate_expected_results_from_prompt(prompt)
    validate_mldsa_response(expected, expected_mode="sigGen")


def test_nist_conformance_sigver_modification_distribution_and_expected_results() -> None:
    prompt = _generate(
        [_sigver_registration(["internal", "external"], PARAMETER_SETS)],
        tests_per_group=1,
        generation_profile=NIST_CONFORMANCE_PROFILE,
    )[0]

    validate_mldsa_vector_set(prompt)
    expected = generate_expected_results_from_prompt(prompt)
    validate_mldsa_response(expected, expected_mode="sigVer")
    expected_by_group = {
        group["tgId"]: {test["tcId"]: test["testPassed"] for test in group["tests"]}
        for group in expected["testGroups"]
    }

    assert all(len(group["tests"]) >= NIST_SIGVER_TESTS_PER_GROUP for group in prompt["testGroups"])
    for group in prompt["testGroups"]:
        modifications = SIGVER_CONFORMANCE_MODIFICATION_SEQUENCE[: len(group["tests"])]
        counts = Counter(modifications)
        assert all(counts[modification] >= 3 for modification in SIGVER_MODIFICATION_CLASSES)

        for test, modification in zip(group["tests"], modifications):
            test_passed = expected_by_group[group["tgId"]][test["tcId"]]
            assert test_passed is (modification == "valid")


def test_nist_conformance_expected_results_validate_matching_and_wrong_response() -> None:
    prompt = _generate(
        [_keygen_registration(PARAMETER_SETS)],
        tests_per_group=1,
        generation_profile=NIST_CONFORMANCE_PROFILE,
    )[0]
    expected = generate_expected_results_from_prompt(prompt)
    validate_mldsa_response(expected, expected_mode="keyGen")

    passed = validate(
        {
            "prompt": prompt,
            "expectedResults": expected,
            "response": copy.deepcopy(expected),
        }
    )
    wrong = copy.deepcopy(expected)
    wrong["testGroups"][0]["tests"][0]["pk"] = _mutate_hex(wrong["testGroups"][0]["tests"][0]["pk"])
    failed = validate(
        {
            "prompt": prompt,
            "expectedResults": expected,
            "response": wrong,
        }
    )

    assert passed["summary"]["failed"] == 0
    assert failed["summary"]["failed"] > 0


def _generate(
    algorithms: List[Dict[str, Any]],
    *,
    tests_per_group: int,
    generation_profile: str = LOCAL_DEBUG_PROFILE,
) -> List[Dict[str, Any]]:
    negotiated = negotiate_mldsa_capabilities(
        validate_registration_container({"algorithms": algorithms})
    )
    return generate_vector_sets_from_negotiated_capabilities(
        negotiated,
        campaign_seed=CAMPAIGN_SEED,
        tests_per_group=tests_per_group,
        generation_profile=generation_profile,
    )


def _keygen_registration(parameter_sets: List[str]) -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": parameter_sets,
    }


def _siggen_registration(
    signature_interfaces: List[str],
    parameter_sets: List[str],
) -> Dict[str, Any]:
    registration: Dict[str, Any] = {
        "algorithm": "ML-DSA",
        "mode": "sigGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "deterministic": [True, False],
        "signatureInterfaces": signature_interfaces,
        "capabilities": [_capability(parameter_sets)],
    }
    if "internal" in signature_interfaces:
        registration["externalMu"] = [False, True]
    if "external" in signature_interfaces:
        registration["preHash"] = ["pure", "preHash"]
    return registration


def _sigver_registration(
    signature_interfaces: List[str],
    parameter_sets: List[str],
) -> Dict[str, Any]:
    registration: Dict[str, Any] = {
        "algorithm": "ML-DSA",
        "mode": "sigVer",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "signatureInterfaces": signature_interfaces,
        "capabilities": [_capability(parameter_sets)],
    }
    if "internal" in signature_interfaces:
        registration["externalMu"] = [False]
    if "external" in signature_interfaces:
        registration["preHash"] = ["pure"]
    return registration


def _capability(parameter_sets: List[str]) -> Dict[str, List[Any]]:
    return {
        "parameterSets": parameter_sets,
        "messageLength": [{"min": 8, "max": 256, "increment": 8}],
        "contextLength": [{"min": 0, "max": 64, "increment": 8}],
        "hashAlgs": ["SHA2-256", "SHA3-256"],
    }


def _hash_algs_in_prompt(prompt: Dict[str, Any]) -> set[str]:
    return {
        test["hashAlg"]
        for group in prompt["testGroups"]
        for test in group["tests"]
        if "hashAlg" in test
    }


def _minimum_kats(
    table: List[Dict[str, Any]],
    parameter_set: str,
    minimum: int,
) -> List[Dict[str, Any]]:
    entries = [kat for kat in table if kat["parameterSet"] == parameter_set]
    if len(entries) >= minimum:
        return entries[:minimum]
    return list(islice(cycle(entries), minimum))


def _unique_tc_ids(prompt: Dict[str, Any]) -> bool:
    tc_ids = [
        test["tcId"]
        for group in prompt["testGroups"]
        for test in group["tests"]
    ]
    return len(tc_ids) == len(set(tc_ids))


def _route_body(value: Any) -> Any:
    if isinstance(value, JSONResponse):
        return value
    return _body_of(value)


def _body_of(value: Any) -> Dict[str, Any]:
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


def _mutate_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]
