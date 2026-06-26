from __future__ import annotations

from .mldsa_constants import MLDSA_NATIVE_ORACLE_DIR, SUPPORTED_PARAMETER_SETS
from .mldsa_errors import (
    MldsaOracleConfigError,
    MldsaOracleError,
    MldsaOracleExecutionError,
    MldsaOracleInputError,
)
from .mldsa_helpers import (
    normalize_hex,
    parse_json_output,
    run_native_binary,
    validate_hex_output,
    validate_parameter_set,
)


_NATIVE_DIR = MLDSA_NATIVE_ORACLE_DIR
_PARAMETER_SETS = SUPPORTED_PARAMETER_SETS


def keygen_internal(parameter_set: str, seed_hex: str) -> dict[str, str]:
    config = validate_parameter_set(parameter_set)
    seed = normalize_hex("seed", seed_hex, int(config["seed_bytes"]))
    completed = run_native_binary(config["keygen_binary"], [seed])
    output = parse_json_output(completed.stdout)
    pk = validate_hex_output(output, "pk", int(config["pk_bytes"]))
    sk = validate_hex_output(output, "sk", int(config["sk_bytes"]))
    return {"pk": pk, "sk": sk}


def siggen_internal(*args, **kwargs) -> dict[str, str]:  # noqa: ANN002, ANN003
    raise NotImplementedError("sigGen oracle is not implemented in Phase 2-2")


def sigver_internal(*args, **kwargs) -> dict[str, bool]:  # noqa: ANN002, ANN003
    raise NotImplementedError("sigVer oracle is not implemented in Phase 2-2")
