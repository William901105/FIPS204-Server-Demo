from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .mldsa_constants import MLDSA_NATIVE_ORACLE_DIR, SUPPORTED_PARAMETER_SETS
from .mldsa_errors import (
    MldsaOracleConfigError,
    MldsaOracleExecutionError,
    MldsaOracleInputError,
)


_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def normalize_hex(name: str, value: str, expected_bytes: Optional[int] = None) -> str:
    if not isinstance(value, str):
        raise MldsaOracleInputError(f"{name} must be a hex string")
    if expected_bytes is not None and len(value) != expected_bytes * 2:
        raise MldsaOracleInputError(
            f"{name} must be exactly {expected_bytes * 2} hex characters"
        )
    if _HEX_RE.fullmatch(value) is None:
        raise MldsaOracleInputError(f"{name} must contain only hex characters")
    return value.upper()


def validate_parameter_set(parameter_set: str) -> Dict[str, Any]:
    if parameter_set not in SUPPORTED_PARAMETER_SETS:
        supported = ", ".join(sorted(SUPPORTED_PARAMETER_SETS))
        raise MldsaOracleInputError(
            f"unsupported parameterSet {parameter_set!r}; supported values: {supported}"
        )
    return SUPPORTED_PARAMETER_SETS[parameter_set]


def run_native_binary(
    binary: Path,
    args: List[str],
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    if not isinstance(binary, Path):
        raise MldsaOracleConfigError("invalid ML-DSA oracle binary configuration")
    if not binary.exists():
        raise MldsaOracleConfigError(
            "native ML-DSA oracle binary not found at "
            f"{binary}. Run `make` in backend/native/mldsa_oracle first."
        )

    try:
        completed = subprocess.run(
            [str(binary), *args],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise MldsaOracleExecutionError(
            f"native ML-DSA oracle timed out after {exc.timeout} seconds"
        ) from exc
    except OSError as exc:
        raise MldsaOracleExecutionError(
            f"failed to execute native ML-DSA oracle {binary}: {exc}"
        ) from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or "no stderr output"
        raise MldsaOracleExecutionError(
            f"native ML-DSA oracle failed with exit code {completed.returncode}: {detail}"
        )

    return completed


def parse_json_output(stdout: str) -> Dict[str, Any]:
    try:
        output = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise MldsaOracleExecutionError(
            f"native ML-DSA oracle returned invalid JSON: {exc}"
        ) from exc

    if not isinstance(output, dict):
        raise MldsaOracleExecutionError("native ML-DSA oracle returned non-object JSON")
    return output


def validate_hex_output(
    output: Dict[str, Any],
    field: str,
    expected_bytes: int,
) -> str:
    value = output.get(field)
    expected_hex_chars = expected_bytes * 2
    if not isinstance(value, str):
        raise MldsaOracleExecutionError(f"native ML-DSA oracle missing {field!r}")
    if len(value) != expected_hex_chars:
        raise MldsaOracleExecutionError(
            f"native ML-DSA oracle returned {field} with {len(value)} hex chars; "
            f"expected {expected_hex_chars}"
        )
    if _HEX_RE.fullmatch(value) is None:
        raise MldsaOracleExecutionError(
            f"native ML-DSA oracle returned non-hex {field}"
        )
    return value.upper()


# Compatibility alias for code that previously referenced the private name.
_NATIVE_DIR = MLDSA_NATIVE_ORACLE_DIR
