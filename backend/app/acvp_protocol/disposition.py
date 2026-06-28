from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from ..acvp_parser import flatten_test_cases, normalize_acvp_json
from .state_machine import VectorSetStatus


ACVP_OVERALL_DISPOSITIONS = {
    "passed",
    "fail",
    "unreceived",
    "incomplete",
    "expired",
    "missing",
    "error",
}
ACVP_TEST_RESULTS = {
    "passed",
    "fail",
    "unreceived",
    "incomplete",
    "expired",
    "missing",
}


def build_acvp_vector_set_results(
    *,
    vector_set: Dict[str, Any],
    validation_result: Optional[Dict[str, Any]],
    response: Optional[Dict[str, Any]],
    expected_results: Optional[Dict[str, Any]],
    show_expected: bool = False,
) -> Dict[str, Any]:
    if vector_set.get("status") == VectorSetStatus.EXPIRED.value:
        return build_expired_results(vector_set)
    if validation_result is None:
        if response is None:
            return build_unreceived_results(vector_set)
        return _results_body(
            _vs_id(vector_set),
            "incomplete",
            _status_tests(expected_results or vector_set.get("prompt"), "incomplete", "test case not processed"),
        )
    if validation_result.get("error") is not None:
        return _results_body(
            _vs_id(vector_set),
            "error",
            _status_tests(expected_results or vector_set.get("prompt"), "incomplete", "test case not processed"),
        )

    expected_map = _test_map(expected_results)
    provided_map = _test_map(response)
    tests: List[Dict[str, Any]] = []
    for case_result in validation_result.get("caseResults", []):
        if not isinstance(case_result, dict):
            continue
        test = _case_result_to_test(
            case_result,
            expected_map,
            provided_map,
            show_expected=show_expected,
        )
        if test is not None:
            tests.append(test)

    disposition = _overall_disposition(vector_set, validation_result)
    return _results_body(_vs_id(vector_set), disposition, tests)


def build_unreceived_results(vector_set: Dict[str, Any]) -> Dict[str, Any]:
    return _results_body(
        _vs_id(vector_set),
        "unreceived",
        _status_tests(
            vector_set.get("expectedResults") or vector_set.get("prompt"),
            "unreceived",
            "response not received",
        ),
    )


def build_expired_results(vector_set: Dict[str, Any]) -> Dict[str, Any]:
    return _results_body(
        _vs_id(vector_set),
        "expired",
        _status_tests(
            vector_set.get("expectedResults") or vector_set.get("prompt"),
            "expired",
            "vector set expired",
        ),
    )


def _overall_disposition(
    vector_set: Dict[str, Any],
    validation_result: Dict[str, Any],
) -> str:
    if vector_set.get("status") == VectorSetStatus.EXPIRED.value:
        return "expired"
    summary = validation_result.get("summary", {})
    if validation_result.get("error") is not None:
        return "error"
    if _count(summary, "failed") > 0 or _count(summary, "malformed") > 0 or _count(summary, "extra") > 0:
        return "fail"
    if _count(summary, "missing") > 0:
        return "missing"

    total = _count(summary, "total")
    processed = (
        _count(summary, "passed")
        + _count(summary, "failed")
        + _count(summary, "missing")
        + _count(summary, "malformed")
    )
    if total > processed:
        return "incomplete"
    if total > 0 and _count(summary, "passed") == total:
        return "passed"
    return "incomplete"


def _case_result_to_test(
    case_result: Dict[str, Any],
    expected_map: Dict[Tuple[Any, Any], Any],
    provided_map: Dict[Tuple[Any, Any], Any],
    *,
    show_expected: bool,
) -> Optional[Dict[str, Any]]:
    tc_id = case_result.get("tcId")
    if tc_id is None:
        return None
    tg_id = case_result.get("tgId")
    status = str(case_result.get("status", "incomplete"))
    result = _per_test_result(status)
    reason = _reason_for_case(case_result, result)
    test: Dict[str, Any] = {
        "tcId": tc_id,
        "result": result,
        "reason": "" if result == "passed" else reason,
    }
    if show_expected and result != "passed":
        key = (tg_id, tc_id)
        test["expected"] = copy.deepcopy(expected_map.get(key))
        test["provided"] = copy.deepcopy(provided_map.get(key))
    return test


def _per_test_result(status: str) -> str:
    if status == "passed":
        return "passed"
    if status == "missing":
        return "missing"
    if status == "unreceived":
        return "unreceived"
    if status == "expired":
        return "expired"
    if status == "incomplete":
        return "incomplete"
    return "fail"


def _reason_for_case(case_result: Dict[str, Any], result: str) -> str:
    if result == "passed":
        return ""
    if result == "missing":
        return "response test case is missing"
    if result == "unreceived":
        return "response not received"
    if result == "incomplete":
        return "test case not processed"
    if result == "expired":
        return "vector set expired"

    failures = case_result.get("failures")
    if isinstance(failures, list) and failures:
        reasons = [
            str(item.get("reason"))
            for item in failures
            if isinstance(item, dict) and item.get("reason")
        ]
        if any(reason == "extra response test case" for reason in reasons):
            return "extra response test case"
        if any(reason in {"missing response field", "missing expected field"} for reason in reasons):
            return "response test case is malformed"
        if reasons:
            return "; ".join(reasons)
    if case_result.get("status") == "extra":
        return "extra response test case"
    if case_result.get("status") == "malformed":
        return "response test case is malformed"
    return "local validation failed"


def _status_tests(data: Any, result: str, reason: str) -> List[Dict[str, Any]]:
    tests: List[Dict[str, Any]] = []
    for case in _flatten_cases(data):
        tc_id = case.get("tcId")
        if tc_id is None:
            continue
        tests.append({"tcId": tc_id, "result": result, "reason": reason})
    return tests


def _test_map(data: Any) -> Dict[Tuple[Any, Any], Any]:
    return {
        (case["tgId"], case["tcId"]): copy.deepcopy(case["test"])
        for case in _flatten_cases(data)
        if case.get("tgId") is not None and case.get("tcId") is not None
    }


def _flatten_cases(data: Any) -> List[Dict[str, Any]]:
    if data is None:
        return []
    try:
        return flatten_test_cases(normalize_acvp_json(data))
    except Exception:
        return []


def _results_body(vs_id: Any, disposition: str, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
    if disposition not in ACVP_OVERALL_DISPOSITIONS:
        disposition = "error"
    normalized_tests = [
        {
            **test,
            "result": test["result"] if test.get("result") in ACVP_TEST_RESULTS else "fail",
        }
        for test in tests
    ]
    return {
        "results": {
            "vsId": vs_id,
            "disposition": disposition,
            "tests": normalized_tests,
        }
    }


def _vs_id(vector_set: Dict[str, Any]) -> Any:
    if vector_set.get("vsId") is not None:
        return vector_set.get("vsId")
    prompt = vector_set.get("prompt")
    if isinstance(prompt, dict):
        return prompt.get("vsId")
    return None


def _count(summary: Dict[str, Any], key: str) -> int:
    value = summary.get(key, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
