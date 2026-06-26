from __future__ import annotations

from typing import Any, Dict, List

from ..crypto_oracle.mldsa_oracle import keygen_internal
from .constants import ALGORITHM, REVISION
from .errors import AcvpSchemaError
from .validators import validate_mldsa_vector_set


def generate_keygen_expected_results_from_prompt(prompt: Any) -> Any:
    vector_set = validate_mldsa_vector_set(prompt)
    _require_keygen_prompt(vector_set)
    expected_results = _build_expected_results(vector_set)

    if isinstance(prompt, list):
        return [_version_object(prompt), expected_results]
    return expected_results


def _require_keygen_prompt(vector_set: Dict[str, Any]) -> None:
    algorithm = vector_set.get("algorithm")
    if algorithm != ALGORITHM:
        raise AcvpSchemaError(
            "unsupported_algorithm",
            f"Unsupported algorithm: {algorithm}",
            "$.algorithm",
        )

    mode = vector_set.get("mode")
    if mode != "keyGen":
        raise AcvpSchemaError(
            "invalid_mode",
            f"Expected ML-DSA keyGen prompt; got mode {mode!r}",
            "$.mode",
        )

    revision = vector_set.get("revision")
    if revision != REVISION:
        raise AcvpSchemaError(
            "unsupported_revision",
            f"Unsupported revision: {revision}",
            "$.revision",
        )


def _build_expected_results(vector_set: Dict[str, Any]) -> Dict[str, Any]:
    expected_results = {
        "vsId": vector_set["vsId"],
        "algorithm": ALGORITHM,
        "mode": "keyGen",
        "revision": REVISION,
        "testGroups": [
            _build_expected_group(group) for group in vector_set["testGroups"]
        ],
    }
    if "isSample" in vector_set:
        expected_results["isSample"] = vector_set["isSample"]
    return expected_results


def _build_expected_group(group: Dict[str, Any]) -> Dict[str, Any]:
    parameter_set = group["parameterSet"]
    tests: List[Dict[str, Any]] = []
    for test in group["tests"]:
        result = keygen_internal(parameter_set, test["seed"])
        tests.append({"tcId": test["tcId"], "pk": result["pk"], "sk": result["sk"]})
    return {"tgId": group["tgId"], "tests": tests}


def _version_object(prompt: List[Any]) -> Dict[str, Any]:
    if prompt and isinstance(prompt[0], dict):
        return dict(prompt[0])
    return {}
