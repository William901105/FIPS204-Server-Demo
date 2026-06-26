from __future__ import annotations

import json
import hashlib
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
    if len(value) % 2 != 0:
        raise MldsaOracleInputError(
            f"{name} must have an even number of hex characters"
        )
    if _HEX_RE.fullmatch(value) is None:
        raise MldsaOracleInputError(f"{name} must contain only hex characters")
    return value.upper()


def normalize_context_hex(value: Optional[str]) -> str:
    if value is None:
        return ""
    context = normalize_hex("context", value)
    if len(context) // 2 > 255:
        raise MldsaOracleInputError("context must be at most 255 bytes")
    return context


def hash_message_for_prehash(message_hex: str, hash_alg: Optional[str]) -> str:
    message = bytes.fromhex(normalize_hex("message", message_hex))
    if hash_alg is None:
        raise MldsaOracleInputError("hashAlg is required when preHash=preHash")

    normalized = hash_alg.upper()
    if normalized == "SHA2-224":
        return hashlib.sha224(message).hexdigest().upper()
    if normalized == "SHA2-256":
        return hashlib.sha256(message).hexdigest().upper()
    if normalized == "SHA2-384":
        return hashlib.sha384(message).hexdigest().upper()
    if normalized == "SHA2-512":
        return hashlib.sha512(message).hexdigest().upper()
    if normalized == "SHA2-512/224":
        return hashlib.new("sha512_224", message).hexdigest().upper()
    if normalized == "SHA2-512/256":
        return hashlib.new("sha512_256", message).hexdigest().upper()
    if normalized == "SHA3-224":
        return hashlib.sha3_224(message).hexdigest().upper()
    if normalized == "SHA3-256":
        return hashlib.sha3_256(message).hexdigest().upper()
    if normalized == "SHA3-384":
        return hashlib.sha3_384(message).hexdigest().upper()
    if normalized == "SHA3-512":
        return hashlib.sha3_512(message).hexdigest().upper()
    if normalized in {"SHAKE-128", "SHAKE-256"}:
        raise MldsaOracleInputError(
            "SHAKE hashAlg is not supported by the Python oracle because "
            "ACVP output length is not represented in this API"
        )
    raise MldsaOracleInputError(f"unsupported hashAlg {hash_alg!r}")


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


def validate_bool_output(output: Dict[str, Any], field: str) -> bool:
    if field not in output:
        raise MldsaOracleExecutionError(f"native ML-DSA oracle missing {field!r}")
    value = output[field]
    if not isinstance(value, bool):
        raise MldsaOracleExecutionError(
            f"native ML-DSA oracle returned non-boolean {field!r}"
        )
    return value


# Compatibility alias for code that previously referenced the private name.
_NATIVE_DIR = MLDSA_NATIVE_ORACLE_DIR
