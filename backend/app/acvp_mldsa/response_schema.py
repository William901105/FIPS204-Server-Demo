from __future__ import annotations

from typing import Any, Dict, List, Optional

from .common import (
    child_path,
    first_present_field,
    require_bool,
    require_enum,
    require_field,
    require_hex_string,
    require_int,
    require_object,
    require_string,
    validate_unique_int_ids,
)
from .constants import ALGORITHM, MODES, REVISION
from .errors import AcvpSchemaError
from .normalize import normalize_acvp_container


def validate_response(payload: Any, expected_mode: Optional[str] = None) -> Dict[str, Any]:
    obj = require_object(normalize_acvp_container(payload), "$")
    mode = _validate_common_response(obj, "$", expected_mode)
    test_groups = require_field(obj, "testGroups", "$")
    _validate_response_groups(test_groups, "$.testGroups", mode)
    return obj


def _validate_common_response(obj: Dict[str, Any], path: str, expected_mode: Optional[str]) -> str:
    require_int(require_field(obj, "vsId", path), child_path(path, "vsId"))

    if "algorithm" in obj:
        algorithm = require_string(obj["algorithm"], child_path(path, "algorithm"))
        if algorithm != ALGORITHM:
            raise AcvpSchemaError(
                "unsupported_algorithm",
                f"Unsupported algorithm: {algorithm}",
                child_path(path, "algorithm"),
            )

    if "revision" in obj:
        revision = require_string(obj["revision"], child_path(path, "revision"))
        if revision != REVISION:
            raise AcvpSchemaError(
                "unsupported_revision",
                f"Unsupported revision: {revision}",
                child_path(path, "revision"),
            )

    if expected_mode is not None:
        return require_enum(expected_mode, MODES, "$.expected_mode", code="invalid_mode")

    if "mode" in obj:
        return require_enum(obj["mode"], MODES, child_path(path, "mode"), code="invalid_mode")

    return _infer_response_mode(obj)


def _validate_response_groups(value: Any, path: str, mode: str) -> None:
    if not isinstance(value, list):
        raise AcvpSchemaError("invalid_type", "Expected array", path)
    if not value:
        raise AcvpSchemaError("invalid_value", "Array must not be empty", path)

    validate_unique_int_ids(value, "tgId", path)
    all_tests: List[Any] = []

    for group_index, item in enumerate(value):
        group_path = child_path(path, group_index)
        group = require_object(item, group_path)
        require_int(require_field(group, "tgId", group_path), child_path(group_path, "tgId"))
        tests = require_field(group, "tests", group_path)
        if not isinstance(tests, list):
            raise AcvpSchemaError("invalid_type", "Expected array", child_path(group_path, "tests"))
        if not tests:
            raise AcvpSchemaError("invalid_value", "Array must not be empty", child_path(group_path, "tests"))
        for test_index, test_item in enumerate(tests):
            test_path = child_path(child_path(group_path, "tests"), test_index)
            test = require_object(test_item, test_path)
            _validate_response_test(test, test_path, mode)
        all_tests.extend(tests)

    validate_unique_int_ids(all_tests, "tcId", "$.testGroups[*].tests")


def _validate_response_test(test: Dict[str, Any], path: str, mode: str) -> None:
    require_int(require_field(test, "tcId", path), child_path(path, "tcId"))
    if mode == "keyGen":
        require_hex_string(require_field(test, "pk", path), child_path(path, "pk"), allow_empty=False)
        require_hex_string(require_field(test, "sk", path), child_path(path, "sk"), allow_empty=False)
    elif mode == "sigGen":
        require_hex_string(require_field(test, "signature", path), child_path(path, "signature"), allow_empty=False)
    elif mode == "sigVer":
        require_bool(require_field(test, "testPassed", path), child_path(path, "testPassed"))
    else:
        raise AcvpSchemaError("invalid_mode", f"Unsupported mode: {mode}", path)


def _infer_response_mode(obj: Dict[str, Any]) -> str:
    groups = obj.get("testGroups")
    if not isinstance(groups, list):
        raise AcvpSchemaError("invalid_mode", "Cannot infer response mode without testGroups", "$.testGroups")

    seen = set()
    for group in groups:
        if not isinstance(group, dict):
            continue
        tests = group.get("tests")
        if not isinstance(tests, list):
            continue
        for test in tests:
            if not isinstance(test, dict):
                continue
            field = first_present_field(test, ("pk", "sk", "signature", "testPassed"))
            if field in {"pk", "sk"}:
                seen.add("keyGen")
            elif field == "signature":
                seen.add("sigGen")
            elif field == "testPassed":
                seen.add("sigVer")

    if len(seen) == 1:
        return next(iter(seen))
    raise AcvpSchemaError(
        "invalid_mode",
        "Cannot infer response mode; provide expected_mode or a top-level mode field",
        "$.mode",
    )

