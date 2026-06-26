from __future__ import annotations

from copy import deepcopy

from app.report import build_report
from app.validator import validate


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"


def test_validator_reports_failed_missing_malformed_and_extra_cases() -> None:
    prompt = _keygen_prompt(test_count=3)
    expected = _keygen_expected(test_count=3)
    response = _keygen_expected(test_count=3)
    response["testGroups"][0]["tests"][0]["pk"] = "AA"
    del response["testGroups"][0]["tests"][1]["sk"]
    response["testGroups"][0]["tests"] = [
        response["testGroups"][0]["tests"][0],
        response["testGroups"][0]["tests"][1],
        {"tcId": 99, "pk": "EE", "sk": "FF"},
    ]

    result = validate(
        {"prompt": prompt, "expectedResults": expected, "response": response}
    )

    assert result["summary"] == {
        "total": 3,
        "passed": 0,
        "failed": 1,
        "missing": 1,
        "malformed": 1,
        "extra": 1,
    }
    assert {failure["reason"] for failure in result["failures"]} == {
        "value mismatch",
        "missing response field",
        "response test case is missing",
        "extra response test case",
    }

    report = build_report("validator-extra-test", result)
    assert report["extraCount"] == 1
    assert "| total | passed | failed | missing | malformed | extra |" in report[
        "markdown"
    ]


def _keygen_prompt(test_count: int) -> dict:
    return {
        "vsId": 8100,
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "tests": [
                    {"tcId": index + 1, "seed": SEED_32_BYTES}
                    for index in range(test_count)
                ],
            }
        ],
    }


def _keygen_expected(test_count: int) -> dict:
    base_tests = [
        {"tcId": 1, "pk": "00", "sk": "11"},
        {"tcId": 2, "pk": "22", "sk": "33"},
        {"tcId": 3, "pk": "44", "sk": "55"},
    ]
    return {
        "vsId": 8100,
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "tests": deepcopy(base_tests[:test_count]),
            }
        ],
    }
