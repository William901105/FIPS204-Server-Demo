from __future__ import annotations

from typing import Optional

from .mldsa_constants import MLDSA_NATIVE_ORACLE_DIR, SUPPORTED_PARAMETER_SETS
from .mldsa_errors import (
    MldsaOracleConfigError,
    MldsaOracleError,
    MldsaOracleExecutionError,
    MldsaOracleInputError,
)
from .mldsa_helpers import (
    hash_message_for_prehash,
    normalize_hex,
    normalize_context_hex,
    parse_json_output,
    run_native_binary,
    validate_bool_output,
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


def siggen_internal(
    parameter_set: str,
    sk_hex: str,
    message_hex: Optional[str] = None,
    *,
    mu_hex: Optional[str] = None,
    rnd_hex: Optional[str] = None,
    external_mu: bool = False,
    deterministic: bool = True,
    signature_interface: str = "internal",
    pre_hash: Optional[str] = None,
    context_hex: Optional[str] = None,
    hash_alg: Optional[str] = None,
) -> dict[str, str]:
    config = validate_parameter_set(parameter_set)
    sk = normalize_hex("sk", sk_hex, int(config["sk_bytes"]))

    if signature_interface == "external":
        args = _build_external_siggen_args(
            config,
            sk,
            message_hex,
            mu_hex=mu_hex,
            rnd_hex=rnd_hex,
            external_mu=external_mu,
            deterministic=deterministic,
            pre_hash=pre_hash,
            context_hex=context_hex,
            hash_alg=hash_alg,
        )
        completed = run_native_binary(config["siggen_binary"], args)
        output = parse_json_output(completed.stdout)
        signature = validate_hex_output(output, "signature", int(config["sig_bytes"]))
        return {"signature": signature}

    if signature_interface != "internal":
        raise MldsaOracleInputError(
            "signatureInterface must be 'internal' or 'external'"
        )
    if pre_hash is not None:
        raise MldsaOracleInputError("preHash is not allowed when signatureInterface=internal")
    if context_hex is not None:
        raise MldsaOracleInputError("context is not allowed when signatureInterface=internal")
    if hash_alg is not None:
        raise MldsaOracleInputError("hashAlg is not allowed when signatureInterface=internal")

    if external_mu:
        if message_hex is not None:
            raise MldsaOracleInputError("message is not allowed when externalMu=true")
        if mu_hex is None:
            raise MldsaOracleInputError("mu is required when externalMu=true")
        input_hex = normalize_hex("mu", mu_hex, int(config["mu_bytes"]))
    else:
        if message_hex is None:
            raise MldsaOracleInputError("message is required when externalMu=false")
        if mu_hex is not None:
            raise MldsaOracleInputError("mu is not allowed when externalMu=false")
        input_hex = normalize_hex("message", message_hex)

    args = ["1" if external_mu else "0", "1" if deterministic else "0", sk, input_hex]
    if deterministic:
        if rnd_hex is not None:
            raise MldsaOracleInputError("rnd is not allowed when deterministic=true")
    else:
        if rnd_hex is None:
            raise MldsaOracleInputError("rnd is required when deterministic=false")
        args.append(normalize_hex("rnd", rnd_hex, int(config["rnd_bytes"])))

    completed = run_native_binary(config["siggen_binary"], args)
    output = parse_json_output(completed.stdout)
    signature = validate_hex_output(output, "signature", int(config["sig_bytes"]))
    return {"signature": signature}


def sigver_internal(
    parameter_set: str,
    pk_hex: str,
    message_hex: Optional[str],
    signature_hex: str,
    *,
    mu_hex: Optional[str] = None,
    external_mu: bool = False,
    signature_interface: str = "internal",
    pre_hash: Optional[str] = None,
    context_hex: Optional[str] = None,
    hash_alg: Optional[str] = None,
) -> dict[str, bool]:
    config = validate_parameter_set(parameter_set)
    pk = normalize_hex("pk", pk_hex, int(config["pk_bytes"]))
    signature = normalize_hex("signature", signature_hex, int(config["sig_bytes"]))

    if signature_interface == "external":
        args = _build_external_sigver_args(
            pk,
            message_hex,
            signature,
            mu_hex=mu_hex,
            external_mu=external_mu,
            pre_hash=pre_hash,
            context_hex=context_hex,
            hash_alg=hash_alg,
        )
        completed = run_native_binary(config["sigver_binary"], args)
        output = parse_json_output(completed.stdout)
        test_passed = validate_bool_output(output, "testPassed")
        return {"testPassed": test_passed}

    if signature_interface != "internal":
        raise MldsaOracleInputError(
            "signatureInterface must be 'internal' or 'external'"
        )
    if pre_hash is not None:
        raise MldsaOracleInputError("preHash is not allowed when signatureInterface=internal")
    if context_hex is not None:
        raise MldsaOracleInputError("context is not allowed when signatureInterface=internal")
    if hash_alg is not None:
        raise MldsaOracleInputError("hashAlg is not allowed when signatureInterface=internal")

    if external_mu:
        if message_hex is not None:
            raise MldsaOracleInputError("message is not allowed when externalMu=true")
        if mu_hex is None:
            raise MldsaOracleInputError("mu is required when externalMu=true")
        input_hex = normalize_hex("mu", mu_hex, int(config["mu_bytes"]))
    else:
        if message_hex is None:
            raise MldsaOracleInputError("message is required when externalMu=false")
        if mu_hex is not None:
            raise MldsaOracleInputError("mu is not allowed when externalMu=false")
        input_hex = normalize_hex("message", message_hex)

    completed = run_native_binary(
        config["sigver_binary"],
        ["1" if external_mu else "0", pk, input_hex, signature],
    )
    output = parse_json_output(completed.stdout)
    test_passed = validate_bool_output(output, "testPassed")
    return {"testPassed": test_passed}


def _build_external_siggen_args(
    config: dict[str, object],
    sk: str,
    message_hex: Optional[str],
    *,
    mu_hex: Optional[str],
    rnd_hex: Optional[str],
    external_mu: bool,
    deterministic: bool,
    pre_hash: Optional[str],
    context_hex: Optional[str],
    hash_alg: Optional[str],
) -> list[str]:
    if external_mu:
        raise MldsaOracleInputError("externalMu is not allowed when signatureInterface=external")
    if mu_hex is not None:
        raise MldsaOracleInputError("mu is not allowed when signatureInterface=external")
    if message_hex is None:
        raise MldsaOracleInputError("message is required when signatureInterface=external")
    if pre_hash not in {"pure", "preHash"}:
        raise MldsaOracleInputError(
            "preHash must be 'pure' or 'preHash' when signatureInterface=external"
        )
    if context_hex is None:
        raise MldsaOracleInputError("context is required when signatureInterface=external")

    context = normalize_context_hex(context_hex)
    deterministic_flag = "1" if deterministic else "0"

    if deterministic:
        if rnd_hex is not None:
            raise MldsaOracleInputError("rnd is not allowed when deterministic=true")
        rnd_args: list[str] = []
    else:
        if rnd_hex is None:
            raise MldsaOracleInputError("rnd is required when deterministic=false")
        rnd_args = [normalize_hex("rnd", rnd_hex, int(config["rnd_bytes"]))]

    if pre_hash == "pure":
        if hash_alg is not None:
            raise MldsaOracleInputError("hashAlg is not allowed when preHash=pure")
        message = normalize_hex("message", message_hex)
        return ["external", "pure", deterministic_flag, sk, message, context, *rnd_args]

    if hash_alg is None:
        raise MldsaOracleInputError("hashAlg is required when preHash=preHash")
    prehashed_message = hash_message_for_prehash(message_hex, hash_alg)
    return [
        "external",
        "preHash",
        deterministic_flag,
        sk,
        prehashed_message,
        context,
        hash_alg.upper(),
        *rnd_args,
    ]


def _build_external_sigver_args(
    pk: str,
    message_hex: Optional[str],
    signature: str,
    *,
    mu_hex: Optional[str],
    external_mu: bool,
    pre_hash: Optional[str],
    context_hex: Optional[str],
    hash_alg: Optional[str],
) -> list[str]:
    if external_mu:
        raise MldsaOracleInputError("externalMu is not allowed when signatureInterface=external")
    if mu_hex is not None:
        raise MldsaOracleInputError("mu is not allowed when signatureInterface=external")
    if message_hex is None:
        raise MldsaOracleInputError("message is required when signatureInterface=external")
    if pre_hash not in {"pure", "preHash"}:
        raise MldsaOracleInputError(
            "preHash must be 'pure' or 'preHash' when signatureInterface=external"
        )
    if context_hex is None:
        raise MldsaOracleInputError("context is required when signatureInterface=external")

    context = normalize_context_hex(context_hex)

    if pre_hash == "pure":
        if hash_alg is not None:
            raise MldsaOracleInputError("hashAlg is not allowed when preHash=pure")
        message = normalize_hex("message", message_hex)
        return ["external", "pure", pk, message, context, signature]

    if hash_alg is None:
        raise MldsaOracleInputError("hashAlg is required when preHash=preHash")
    prehashed_message = hash_message_for_prehash(message_hex, hash_alg)
    return [
        "external",
        "preHash",
        pk,
        prehashed_message,
        context,
        hash_alg.upper(),
        signature,
    ]
