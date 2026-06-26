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
    mldsa_sigver,
    validate_import,
)
from app.models import (
    GeneratedKeygenImportRequest,
    LoadSampleRequest,
    MldsaKeygenExpectedResultsRequest,
    MldsaKeygenRequest,
    MldsaSigGenRequest,
    MldsaSigVerRequest,
    ValidateRequest,
)


SAMPLE_ROOT = Path(__file__).resolve().parents[2] / "sample-data"
KEYGEN_SAMPLE = SAMPLE_ROOT / "ML-DSA-keyGen-FIPS204"
SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
MESSAGE_HEX = "00010203040506070809"
CONTEXT_HEX = "0A0B0C"
BAD_CONTEXT_HEX = "0A0B0D"
MU_64_BYTES = (
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
)
BAD_MU_64_BYTES = (
    "100102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
)
RND_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"


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


def test_siggen_endpoint_route_function_is_deterministic() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    request = MldsaSigGenRequest(
        parameterSet="ML-DSA-44",
        sk=keygen.sk,
        message=MESSAGE_HEX,
    )

    first = mldsa_siggen(request)
    second = mldsa_siggen(request)

    assert first.signature == second.signature


def test_siggen_endpoint_route_function_supports_phase25_modes() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    requests = [
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            sk=keygen.sk,
            message=MESSAGE_HEX,
        ),
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            externalMu=False,
            deterministic=False,
            sk=keygen.sk,
            message=MESSAGE_HEX,
            rnd=RND_32_BYTES,
        ),
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            externalMu=True,
            deterministic=True,
            sk=keygen.sk,
            mu=MU_64_BYTES,
        ),
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            externalMu=True,
            deterministic=False,
            sk=keygen.sk,
            mu=MU_64_BYTES,
            rnd=RND_32_BYTES,
        ),
    ]

    responses = [mldsa_siggen(request) for request in requests]

    for request, response in zip(requests, responses):
        assert response.algorithm == "ML-DSA"
        assert response.mode == "sigGen"
        assert response.revision == "FIPS204"
        assert response.parameterSet == request.parameterSet
        assert response.signatureInterface == "internal"
        assert response.externalMu is request.externalMu
        assert response.deterministic is request.deterministic
        assert len(response.signature) == 2420 * 2
        assert response.signature == response.signature.upper()


def test_siggen_endpoint_route_function_supports_external_pure_and_prehash() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    pure = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            deterministic=True,
            sk=keygen.sk,
            message=MESSAGE_HEX,
            preHash="pure",
            context=CONTEXT_HEX.lower(),
        )
    )
    pure_randomized = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            deterministic=False,
            sk=keygen.sk,
            message=MESSAGE_HEX,
            preHash="pure",
            context=CONTEXT_HEX,
            rnd=RND_32_BYTES,
        )
    )
    prehash = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            deterministic=True,
            sk=keygen.sk,
            message=MESSAGE_HEX,
            preHash="preHash",
            context=CONTEXT_HEX,
            hashAlg="SHA2-256",
        )
    )

    for response in (pure, pure_randomized, prehash):
        assert response.algorithm == "ML-DSA"
        assert response.mode == "sigGen"
        assert response.revision == "FIPS204"
        assert response.parameterSet == "ML-DSA-44"
        assert response.signatureInterface == "external"
        assert response.externalMu is False
        assert len(response.signature) == 2420 * 2
        assert response.signature == response.signature.upper()

    assert pure.deterministic is True
    assert pure.preHash == "pure"
    assert pure.context == CONTEXT_HEX
    assert pure.hashAlg is None
    assert pure_randomized.deterministic is False
    assert prehash.preHash == "preHash"
    assert prehash.context == CONTEXT_HEX
    assert prehash.hashAlg == "SHA2-256"


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


def test_siggen_endpoint_route_rejects_phase25_invalid_combinations() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    invalid_payloads = (
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": True,
            "deterministic": True,
            "sk": keygen.sk,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "deterministic": False,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
            "rnd": RND_32_BYTES,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
            "preHash": "pure",
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
            "preHash": "pure",
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
            "preHash": "pure",
            "context": CONTEXT_HEX,
            "hashAlg": "SHA2-256",
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
            "preHash": "preHash",
            "context": CONTEXT_HEX,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "deterministic": True,
            "sk": keygen.sk,
            "message": MESSAGE_HEX,
            "preHash": "preHash",
            "context": CONTEXT_HEX,
            "hashAlg": "SHAKE-128",
        },
    )

    for payload in invalid_payloads:
        with pytest.raises(HTTPException) as exc_info:
            mldsa_siggen(payload)

        assert exc_info.value.status_code == 400


def test_sigver_endpoint_route_function_returns_true_and_false() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    signature = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            sk=keygen.sk,
            message=MESSAGE_HEX,
        )
    ).signature

    valid = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            pk=keygen.pk,
            message=MESSAGE_HEX,
            signature=signature,
        )
    )
    bad_message = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            pk=keygen.pk,
            message="00010203040506070808",
            signature=signature,
        )
    )

    assert valid.algorithm == "ML-DSA"
    assert valid.mode == "sigVer"
    assert valid.revision == "FIPS204"
    assert valid.parameterSet == "ML-DSA-44"
    assert valid.signatureInterface == "internal"
    assert valid.externalMu is False
    assert valid.testPassed is True
    assert bad_message.testPassed is False


def test_sigver_endpoint_route_function_supports_external_mu() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    signature = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            externalMu=True,
            sk=keygen.sk,
            mu=MU_64_BYTES,
        )
    ).signature

    valid = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            externalMu=True,
            pk=keygen.pk,
            mu=MU_64_BYTES,
            signature=signature,
        )
    )
    bad_mu = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            externalMu=True,
            pk=keygen.pk,
            mu=BAD_MU_64_BYTES,
            signature=signature,
        )
    )

    assert valid.algorithm == "ML-DSA"
    assert valid.mode == "sigVer"
    assert valid.revision == "FIPS204"
    assert valid.parameterSet == "ML-DSA-44"
    assert valid.signatureInterface == "internal"
    assert valid.externalMu is True
    assert valid.testPassed is True
    assert bad_mu.testPassed is False


def test_sigver_endpoint_route_function_supports_external_pure_and_prehash() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    pure_signature = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            deterministic=True,
            sk=keygen.sk,
            message=MESSAGE_HEX,
            preHash="pure",
            context=CONTEXT_HEX,
        )
    ).signature
    prehash_signature = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            deterministic=True,
            sk=keygen.sk,
            message=MESSAGE_HEX,
            preHash="preHash",
            context=CONTEXT_HEX,
            hashAlg="SHA2-256",
        )
    ).signature

    pure_valid = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            pk=keygen.pk,
            message=MESSAGE_HEX,
            signature=pure_signature,
            preHash="pure",
            context=CONTEXT_HEX.lower(),
        )
    )
    pure_bad_context = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            pk=keygen.pk,
            message=MESSAGE_HEX,
            signature=pure_signature,
            preHash="pure",
            context=BAD_CONTEXT_HEX,
        )
    )
    prehash_valid = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            pk=keygen.pk,
            message=MESSAGE_HEX,
            signature=prehash_signature,
            preHash="preHash",
            context=CONTEXT_HEX,
            hashAlg="SHA2-256",
        )
    )
    prehash_bad_message = mldsa_sigver(
        MldsaSigVerRequest(
            parameterSet="ML-DSA-44",
            signatureInterface="external",
            pk=keygen.pk,
            message="00010203040506070808",
            signature=prehash_signature,
            preHash="preHash",
            context=CONTEXT_HEX,
            hashAlg="SHA2-256",
        )
    )

    assert pure_valid.signatureInterface == "external"
    assert pure_valid.externalMu is False
    assert pure_valid.preHash == "pure"
    assert pure_valid.context == CONTEXT_HEX
    assert pure_valid.hashAlg is None
    assert pure_valid.testPassed is True
    assert pure_bad_context.testPassed is False
    assert prehash_valid.preHash == "preHash"
    assert prehash_valid.context == CONTEXT_HEX
    assert prehash_valid.hashAlg == "SHA2-256"
    assert prehash_valid.testPassed is True
    assert prehash_bad_message.testPassed is False


def test_sigver_endpoint_route_rejects_unsupported_flags() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    signature = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            sk=keygen.sk,
            message=MESSAGE_HEX,
        )
    ).signature

    for payload in (
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": True,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
        },
    ):
        with pytest.raises(HTTPException) as exc_info:
            mldsa_sigver(payload)

        assert exc_info.value.status_code == 400


def test_sigver_endpoint_route_rejects_phase25_invalid_combinations() -> None:
    keygen = mldsa_keygen(
        MldsaKeygenRequest(parameterSet="ML-DSA-44", seed=SEED_32_BYTES)
    )
    signature = mldsa_siggen(
        MldsaSigGenRequest(
            parameterSet="ML-DSA-44",
            sk=keygen.sk,
            message=MESSAGE_HEX,
        )
    ).signature
    invalid_payloads = (
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "pk": keygen.pk,
            "signature": signature,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": True,
            "pk": keygen.pk,
            "signature": signature,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "mu": MU_64_BYTES,
            "signature": signature,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "internal",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
            "preHash": "pure",
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
            "preHash": "pure",
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
            "preHash": "pure",
            "context": CONTEXT_HEX,
            "hashAlg": "SHA2-256",
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
            "preHash": "preHash",
            "context": CONTEXT_HEX,
        },
        {
            "parameterSet": "ML-DSA-44",
            "signatureInterface": "external",
            "externalMu": False,
            "pk": keygen.pk,
            "message": MESSAGE_HEX,
            "signature": signature,
            "preHash": "preHash",
            "context": CONTEXT_HEX,
            "hashAlg": "SHAKE-256",
        },
    )

    for payload in invalid_payloads:
        with pytest.raises(HTTPException) as exc_info:
            mldsa_sigver(payload)

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
