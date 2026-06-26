from __future__ import annotations

import copy
from typing import Any, Dict

import pytest
from fastapi import HTTPException

from app.acvp_mldsa.expected import generate_expected_results_from_prompt
from app.crypto_oracle.mldsa_oracle import keygen_internal, siggen_internal
from app.main import (
    IMPORT_STORE,
    get_report,
    import_generated_keygen_bundle,
    import_generated_mldsa_bundle,
    import_generated_mldsa_bundle_and_validate,
    validate_import,
)
from app.models import (
    GeneratedKeygenImportRequest,
    GeneratedMldsaImportRequest,
    ValidateRequest,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
MESSAGE_HEX = "00010203040506070809"
BAD_MESSAGE_HEX = "00010203040506070808"


def test_generated_import_supports_keygen_validate_and_report() -> None:
    prompt = _keygen_prompt()
    response = generate_expected_results_from_prompt(prompt)

    imported = import_generated_mldsa_bundle(
        GeneratedMldsaImportRequest(
            prompt=prompt,
            response=response,
            label="generated keyGen",
        )
    )
    validation = validate_import(ValidateRequest(importId=imported.importId))
    report = get_report(imported.importId)

    assert imported.mode == "keyGen"
    assert IMPORT_STORE[imported.importId]["generatedExpectedResults"] is True
    assert validation["summary"]["total"] == 1
    assert validation["summary"]["passed"] == 1
    assert report["passedCount"] == 1


def test_generated_import_supports_siggen() -> None:
    keypair = _keypair()
    prompt = _siggen_prompt(keypair["sk"])
    response = generate_expected_results_from_prompt(prompt)

    imported = import_generated_mldsa_bundle(
        GeneratedMldsaImportRequest(prompt=prompt, response=response)
    )
    validation = validate_import(ValidateRequest(importId=imported.importId))

    assert imported.mode == "sigGen"
    assert validation["summary"]["passed"] == validation["summary"]["total"]
    assert validation["summary"]["failed"] == 0


def test_generated_import_supports_sigver() -> None:
    keypair = _keypair()
    signature = siggen_internal("ML-DSA-44", keypair["sk"], MESSAGE_HEX)["signature"]
    prompt = _sigver_prompt(keypair["pk"], signature)
    response = generate_expected_results_from_prompt(prompt)

    imported = import_generated_mldsa_bundle(
        GeneratedMldsaImportRequest(prompt=prompt, response=response)
    )
    validation = validate_import(ValidateRequest(importId=imported.importId))

    assert imported.mode == "sigVer"
    assert validation["summary"]["passed"] == 2
    assert validation["summary"]["failed"] == 0


def test_generated_and_validate_endpoint_returns_import_validation_and_report() -> None:
    prompt = _siggen_prompt(_keypair()["sk"])
    response = generate_expected_results_from_prompt(prompt)

    body = import_generated_mldsa_bundle_and_validate(
        GeneratedMldsaImportRequest(
            prompt=prompt,
            response=response,
            label="generated and validate",
        )
    )

    assert sorted(body) == ["import", "report", "validationResult"]
    assert body["import"]["mode"] == "sigGen"
    assert body["validationResult"]["summary"]["passed"] == 1
    assert "markdown" in body["report"]


def test_generated_import_rejects_malformed_response_schema() -> None:
    prompt = _siggen_prompt(_keypair()["sk"])
    response = generate_expected_results_from_prompt(prompt)
    del response["testGroups"][0]["tests"][0]["signature"]

    with pytest.raises(HTTPException) as exc_info:
        import_generated_mldsa_bundle(
            GeneratedMldsaImportRequest(prompt=prompt, response=response)
        )

    assert exc_info.value.status_code == 400


def test_validate_reports_wrong_missing_and_extra_generated_responses() -> None:
    prompt = _siggen_prompt(_keypair()["sk"], test_count=2)
    response = generate_expected_results_from_prompt(prompt)
    wrong = copy.deepcopy(response)
    wrong["testGroups"][0]["tests"][0]["signature"] = _flip_first_hex_char(
        wrong["testGroups"][0]["tests"][0]["signature"]
    )
    wrong["testGroups"][0]["tests"].append(
        copy.deepcopy(wrong["testGroups"][0]["tests"][1])
    )
    wrong["testGroups"][0]["tests"][-1]["tcId"] = 99
    wrong["testGroups"][0]["tests"] = [
        wrong["testGroups"][0]["tests"][0],
        wrong["testGroups"][0]["tests"][2],
    ]

    imported = import_generated_mldsa_bundle(
        GeneratedMldsaImportRequest(prompt=prompt, response=wrong)
    )
    validation = validate_import(ValidateRequest(importId=imported.importId))

    assert validation["summary"]["failed"] == 1
    assert validation["summary"]["missing"] == 1
    assert validation["summary"]["extra"] == 1


def test_old_generated_keygen_endpoint_still_works() -> None:
    prompt = _keygen_prompt()
    response = generate_expected_results_from_prompt(prompt)

    imported = import_generated_keygen_bundle(
        GeneratedKeygenImportRequest(prompt=prompt, response=response)
    )
    validation = validate_import(ValidateRequest(importId=imported.importId))

    assert imported.mode == "keyGen"
    assert validation["summary"]["passed"] == 1


def _keypair() -> Dict[str, str]:
    return keygen_internal("ML-DSA-44", SEED_32_BYTES)


def _keygen_prompt() -> Dict[str, Any]:
    return {
        "vsId": 8200,
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


def _siggen_prompt(sk: str, test_count: int = 1) -> Dict[str, Any]:
    return {
        "vsId": 8201,
        "algorithm": "ML-DSA",
        "mode": "sigGen",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "signatureInterface": "internal",
                "externalMu": False,
                "deterministic": True,
                "tests": [
                    {"tcId": index + 1, "sk": sk, "message": MESSAGE_HEX}
                    for index in range(test_count)
                ],
            }
        ],
    }


def _sigver_prompt(pk: str, signature: str) -> Dict[str, Any]:
    return {
        "vsId": 8202,
        "algorithm": "ML-DSA",
        "mode": "sigVer",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "signatureInterface": "internal",
                "externalMu": False,
                "tests": [
                    {
                        "tcId": 1,
                        "pk": pk,
                        "message": MESSAGE_HEX,
                        "signature": signature,
                    },
                    {
                        "tcId": 2,
                        "pk": pk,
                        "message": BAD_MESSAGE_HEX,
                        "signature": signature,
                    },
                ],
            }
        ],
    }


def _flip_first_hex_char(value: str) -> str:
    first = "0" if value[0] != "0" else "1"
    return first + value[1:]
