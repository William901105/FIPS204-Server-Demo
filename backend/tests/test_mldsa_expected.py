from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

from app.acvp_mldsa.expected import generate_keygen_expected_results_from_prompt
from app.crypto_oracle import mldsa_oracle
from app.main import (
    app,
    get_report,
    import_generated_keygen_bundle,
    load_sample_import,
    mldsa_keygen,
    mldsa_keygen_expected_results,
    mldsa_siggen,
    validate_import,
)
from app.models import (
    GeneratedKeygenImportRequest,
    LoadSampleRequest,
    MldsaKeygenExpectedResultsRequest,
    MldsaKeygenRequest,
    MldsaSigGenRequest,
    ValidateRequest,
)


SAMPLE_ROOT = Path(__file__).resolve().parents[2] / "sample-data"
KEYGEN_SAMPLE = SAMPLE_ROOT / "ML-DSA-keyGen-FIPS204"
SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
MESSAGE_HEX = "00010203040506070809"


def test_app_import_does_not_fail() -> None:
    assert app.title


def test_keygen_endpoint_still_available() -> None:
    body = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )

    assert body.algorithm == "ML-DSA"
    assert body.mode == "keyGen"
    assert body.revision == "FIPS204"
    assert len(body.pk) == 1312 * 2
    assert len(body.sk) == 2560 * 2


def test_siggen_endpoint_route_function_generates_signature() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )

    body = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            sk=keygen.sk,
            message=MESSAGE_HEX,
        )
    )

    assert body.algorithm == "ML-DSA"
    assert body.mode == "sigGen"
    assert body.revision == "FIPS204"
    assert body.parameterSet == "ML-DSA-44"
    assert body.signatureInterface == "internal"
    assert body.externalMu is False
    assert body.deterministic is True
    assert len(body.signature) == 2420 * 2
    assert body.signature == body.signature.upper()


def test_siggen_endpoint_route_rejects_unsupported_flags() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )

    with pytest.raises(HTTPException) as exc_info:
        mldsa_siggen(
            {
                "parameterSet": "ML-DSA-44",
                "signatureInterface": "internal",
                "externalMu": True,
                "deterministic": True,
                "sk": keygen.sk,
                "message": MESSAGE_HEX,
            }
        )

    assert exc_info.value.status_code == 400


def test_generate_keygen_expected_results_matches_sample_subset() -> None:
    prompt = _small_keygen_prompt(test_count=2)
    generated = generate_keygen_expected_results_from_prompt(prompt)

    assert generated == _sample_expected_subset(prompt)


def test_generate_keygen_expected_results_preserves_array_style() -> None:
    prompt = _small_keygen_prompt(test_count=1)
    generated = generate_keygen_expected_results_from_prompt([{"acvVersion": "1.0"}, prompt])

    assert isinstance(generated, list)
    assert generated[0] == {"acvVersion": "1.0"}
    assert generated[1]["vsId"] == prompt["vsId"]
    assert generated[1]["testGroups"][0]["tgId"] == prompt["testGroups"][0]["tgId"]


def test_expected_results_endpoint_generates_keygen_results() -> None:
    prompt = _small_keygen_prompt(test_count=2)

    body = mldsa_keygen_expected_results(
        MldsaKeygenExpectedResultsRequest(prompt=prompt),
    )

    expected_results = body.expectedResults
    tests = expected_results["testGroups"][0]["tests"]
    assert body.algorithm == "ML-DSA"
    assert body.mode == "keyGen"
    assert body.revision == "FIPS204"
    assert expected_results["vsId"] == prompt["vsId"]
    assert expected_results["testGroups"][0]["tgId"] == prompt["testGroups"][0]["tgId"]
    assert tests[0]["tcId"] == prompt["testGroups"][0]["tests"][0]["tcId"]
    assert "pk" in tests[0]
    assert "sk" in tests[0]
    assert "seed" not in tests[0]
    assert expected_results["isSample"] == prompt["isSample"]


def test_expected_results_endpoint_rejects_unsupported_mode() -> None:
    prompt = _read_json(SAMPLE_ROOT / "ML-DSA-sigGen-FIPS204" / "prompt.json")

    with pytest.raises(HTTPException) as exc_info:
        mldsa_keygen_expected_results(MldsaKeygenExpectedResultsRequest(prompt=prompt))

    assert exc_info.value.status_code == 400
    assert "keyGen" in str(exc_info.value.detail)


def test_expected_results_endpoint_rejects_invalid_seed() -> None:
    prompt = _small_keygen_prompt(test_count=1)
    prompt["testGroups"][0]["tests"][0]["seed"] = "00"

    with pytest.raises(HTTPException) as exc_info:
        mldsa_keygen_expected_results(MldsaKeygenExpectedResultsRequest(prompt=prompt))

    assert exc_info.value.status_code == 400
    assert "64 hex" in str(exc_info.value.detail)


def test_expected_results_endpoint_reports_missing_native_binary(monkeypatch) -> None:
    prompt = _small_keygen_prompt(test_count=1)
    missing_binary = Path("/tmp/acvp-missing-mldsa44-keygen-oracle")
    monkeypatch.setitem(
        mldsa_oracle._PARAMETER_SETS["ML-DSA-44"],  # noqa: SLF001
        "keygen_binary",
        missing_binary,
    )

    with pytest.raises(HTTPException) as exc_info:
        mldsa_keygen_expected_results(MldsaKeygenExpectedResultsRequest(prompt=prompt))

    assert exc_info.value.status_code == 500
    assert "Run `make` in backend/native/mldsa_oracle first." in str(exc_info.value.detail)


def test_generated_keygen_import_validate_report_flow() -> None:
    prompt = _small_keygen_prompt(test_count=2)
    response_payload = _read_json(KEYGEN_SAMPLE / "response.pass.json")

    imported = import_generated_keygen_bundle(
        GeneratedKeygenImportRequest(
            prompt=prompt,
            response=response_payload,
            label="generated keyGen test",
        )
    )

    import_id = imported.importId
    validation = validate_import(ValidateRequest(importId=import_id))
    assert validation["summary"]["passed"] == 2

    report = get_report(import_id)
    assert report["passedCount"] == 2


def test_sample_upload_validate_report_workflow_still_works() -> None:
    imported = load_sample_import(
        LoadSampleRequest(sampleName="ML-DSA-keyGen-FIPS204", responseVariant="pass")
    )

    import_id = imported.importId
    validation = validate_import(ValidateRequest(importId=import_id))
    assert validation["summary"]["failed"] == 0

    report = get_report(import_id)
    assert report["failedCount"] == 0


def test_health_route_still_available() -> None:
    from app.main import health

    assert health() == {"status": "ok"}


def test_generated_keygen_expected_results_exact_match_sample() -> None:
    prompt = _read_json(KEYGEN_SAMPLE / "prompt.json")
    sample_expected = _read_json(KEYGEN_SAMPLE / "expectedResults.json")

    generated = generate_keygen_expected_results_from_prompt(prompt)

    assert generated == sample_expected


def _small_keygen_prompt(test_count: int) -> dict[str, Any]:
    prompt = _read_json(KEYGEN_SAMPLE / "prompt.json")
    small_prompt = copy.deepcopy(prompt)
    first_group = copy.deepcopy(small_prompt["testGroups"][0])
    first_group["tests"] = first_group["tests"][:test_count]
    small_prompt["testGroups"] = [first_group]
    return small_prompt


def _sample_expected_subset(prompt: dict[str, Any]) -> dict[str, Any]:
    sample_expected = _read_json(KEYGEN_SAMPLE / "expectedResults.json")
    expected_groups = {group["tgId"]: group for group in sample_expected["testGroups"]}
    groups = []
    for group in prompt["testGroups"]:
        sample_group = expected_groups[group["tgId"]]
        expected_tests = {test["tcId"]: test for test in sample_group["tests"]}
        groups.append(
            {
                "tgId": group["tgId"],
                "tests": [
                    copy.deepcopy(expected_tests[test["tcId"]])
                    for test in group["tests"]
                ],
            }
        )

    return {
        "vsId": sample_expected["vsId"],
        "algorithm": sample_expected["algorithm"],
        "mode": sample_expected["mode"],
        "revision": sample_expected["revision"],
        "isSample": sample_expected["isSample"],
        "testGroups": groups,
    }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
