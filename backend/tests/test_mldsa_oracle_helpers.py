from __future__ import annotations

from pathlib import Path

import pytest

from app.crypto_oracle.mldsa_constants import SUPPORTED_PARAMETER_SETS
from app.crypto_oracle.mldsa_errors import (
    MldsaOracleExecutionError,
    MldsaOracleInputError,
)
from app.crypto_oracle.mldsa_helpers import (
    normalize_hex,
    parse_json_output,
    validate_parameter_set,
)
from app.crypto_oracle.mldsa_oracle import (
    keygen_internal,
    siggen_internal,
    sigver_internal,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
SKIP_NATIVE_REASON = (
    "native keyGen oracle binary not built; run make in backend/native/mldsa_oracle"
)


def test_normalize_hex_uppercases_lowercase() -> None:
    assert normalize_hex("seed", "0a0b", expected_bytes=2) == "0A0B"


def test_normalize_hex_rejects_invalid_hex() -> None:
    with pytest.raises(MldsaOracleInputError):
        normalize_hex("seed", "not-hex", expected_bytes=32)


def test_normalize_hex_rejects_wrong_length() -> None:
    with pytest.raises(MldsaOracleInputError):
        normalize_hex("seed", "00", expected_bytes=32)


def test_validate_parameter_set_rejects_unsupported_value() -> None:
    with pytest.raises(MldsaOracleInputError):
        validate_parameter_set("ML-DSA-99")


def test_parse_json_output_accepts_valid_json() -> None:
    assert parse_json_output('{"pk": "AA", "sk": "BB"}') == {"pk": "AA", "sk": "BB"}


def test_parse_json_output_rejects_invalid_json() -> None:
    with pytest.raises(MldsaOracleExecutionError):
        parse_json_output("{not-json")


def test_keygen_internal_returns_deterministic_uppercase_hex() -> None:
    _skip_if_keygen_binary_missing("ML-DSA-44")

    first = keygen_internal("ML-DSA-44", SEED_32_BYTES.lower())
    second = keygen_internal("ML-DSA-44", SEED_32_BYTES.lower())

    assert first == second
    assert len(first["pk"]) == 1312 * 2
    assert len(first["sk"]) == 2560 * 2
    assert first["pk"] == first["pk"].upper()
    assert first["sk"] == first["sk"].upper()


def test_future_oracle_stubs_are_not_implemented() -> None:
    with pytest.raises(NotImplementedError, match="sigGen oracle is not implemented"):
        siggen_internal()

    with pytest.raises(NotImplementedError, match="sigVer oracle is not implemented"):
        sigver_internal()


def _skip_if_keygen_binary_missing(parameter_set: str) -> None:
    binary = SUPPORTED_PARAMETER_SETS[parameter_set]["keygen_binary"]
    if not isinstance(binary, Path) or not binary.exists():
        pytest.skip(SKIP_NATIVE_REASON)
