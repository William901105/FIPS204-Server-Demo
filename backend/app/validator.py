from __future__ import annotations

from collections import Counter
from typing import Any

from .acvp_parser import (
    extract_algorithm_metadata,
    flatten_test_cases,
    index_test_cases,
    normalize_acvp_json,
)


MODE_FIELDS = {
    "keygen": ["pk", "sk"],
    "siggen": ["signature"],
    "sigver": ["testPassed"],
}


def required_fields_for_mode(mode: Any) -> list[str]:
    normalized = str(mode or "").replace("-", "").lower()
    return MODE_FIELDS.get(normalized, [])


def validate_keygen(expected_tc: dict[str, Any], response_tc: dict[str, Any]) -> list[dict[str, Any]]:
    return _compare_fields(expected_tc, response_tc, MODE_FIELDS["keygen"])


def validate_siggen(expected_tc: dict[str, Any], response_tc: dict[str, Any]) -> list[dict[str, Any]]:
    return _compare_fields(expected_tc, response_tc, MODE_FIELDS["siggen"])


def validate_sigver(expected_tc: dict[str, Any], response_tc: dict[str, Any]) -> list[dict[str, Any]]:
    return _compare_fields(expected_tc, response_tc, MODE_FIELDS["sigver"])


def validate(imported_bundle: dict[str, Any]) -> dict[str, Any]:
    prompt_vs = normalize_acvp_json(imported_bundle["prompt"])
    expected_vs = normalize_acvp_json(imported_bundle["expectedResults"])
    response_vs = normalize_acvp_json(imported_bundle["response"])

    metadata = extract_algorithm_metadata(prompt_vs)
    if not metadata.get("mode"):
        metadata = extract_algorithm_metadata(expected_vs)

    fields = required_fields_for_mode(metadata.get("mode"))
    if not fields:
        raise ValueError(f"Unsupported ML-DSA mode: {metadata.get('mode')!r}")

    prompt_index = index_test_cases(prompt_vs)
    response_index = index_test_cases(response_vs)
    expected_cases = flatten_test_cases(expected_vs)
    expected_index = {
        (case["tgId"], case["tcId"]): case["test"]
        for case in expected_cases
        if case.get("tgId") is not None and case.get("tcId") is not None
    }

    case_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for expected_case in expected_cases:
        tg_id = expected_case["tgId"]
        tc_id = expected_case["tcId"]
        expected_tc = expected_case["test"]
        response_tc = response_index.get((tg_id, tc_id))
        prompt_tc = prompt_index.get((tg_id, tc_id))

        if response_tc is None:
            status = "missing"
            failure = {
                "tgId": tg_id,
                "tcId": tc_id,
                "field": "tcId",
                "reason": "response test case is missing",
                "expected": tc_id,
                "provided": None,
            }
            case_failures = [failure]
            failures.append(failure)
        else:
            case_failures = _validate_fields(expected_tc, response_tc, fields, tg_id, tc_id)
            if not case_failures:
                status = "passed"
            elif any(item["reason"] in {"missing response field", "missing expected field"} for item in case_failures):
                status = "malformed"
            else:
                status = "failed"
            failures.extend(case_failures)

        counts[status] += 1
        case_results.append(
            {
                "tgId": tg_id,
                "tcId": tc_id,
                "status": status,
                "prompt": prompt_tc,
                "expected": expected_tc,
                "response": response_tc,
                "failures": case_failures,
                "group": expected_case["group"],
            }
        )

    for (tg_id, tc_id), response_tc in sorted(
        response_index.items(),
        key=lambda item: (str(item[0][0]), str(item[0][1])),
    ):
        if (tg_id, tc_id) in expected_index:
            continue
        status = "extra"
        failure = {
            "tgId": tg_id,
            "tcId": tc_id,
            "field": "tcId",
            "reason": "extra response test case",
            "expected": None,
            "provided": tc_id,
        }
        failures.append(failure)
        counts[status] += 1
        case_results.append(
            {
                "tgId": tg_id,
                "tcId": tc_id,
                "status": status,
                "prompt": prompt_index.get((tg_id, tc_id)),
                "expected": None,
                "response": response_tc,
                "failures": [failure],
                "group": None,
            }
        )

    summary = {
        "total": len(expected_cases),
        "passed": counts["passed"],
        "failed": counts["failed"],
        "missing": counts["missing"],
        "malformed": counts["malformed"],
        "extra": counts["extra"],
    }

    return {
        "metadata": metadata,
        "summary": summary,
        "failures": failures,
        "caseResults": case_results,
    }


def _validate_fields(
    expected_tc: dict[str, Any],
    response_tc: dict[str, Any],
    fields: list[str],
    tg_id: Any,
    tc_id: Any,
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for field in fields:
        if field not in expected_tc:
            failures.append(
                {
                    "tgId": tg_id,
                    "tcId": tc_id,
                    "field": field,
                    "reason": "missing expected field",
                    "expected": "<present>",
                    "provided": None,
                }
            )
            continue
        if field not in response_tc:
            failures.append(
                {
                    "tgId": tg_id,
                    "tcId": tc_id,
                    "field": field,
                    "reason": "missing response field",
                    "expected": _display_value(expected_tc.get(field)),
                    "provided": None,
                }
            )
            continue
        if response_tc[field] != expected_tc[field]:
            failures.append(
                {
                    "tgId": tg_id,
                    "tcId": tc_id,
                    "field": field,
                    "reason": "value mismatch",
                    "expected": _display_value(expected_tc.get(field)),
                    "provided": _display_value(response_tc.get(field)),
                }
            )
    return failures


def _compare_fields(
    expected_tc: dict[str, Any],
    response_tc: dict[str, Any],
    fields: list[str],
) -> list[dict[str, Any]]:
    return _validate_fields(expected_tc, response_tc, fields, expected_tc.get("tgId"), expected_tc.get("tcId"))


def _display_value(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 160:
        return f"{value[:72]}...{value[-32:]} ({len(value)} chars)"
    return value
