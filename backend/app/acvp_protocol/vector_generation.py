from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from ..acvp_mldsa.constants import ALGORITHM, REVISION
from ..crypto_oracle.mldsa_constants import SUPPORTED_PARAMETER_SETS
from ..crypto_oracle.mldsa_oracle import keygen_internal, siggen_internal


GENERATION_PROFILE = "phase-3-4-deterministic-local"
FALLBACK_CAMPAIGN_SEED_SALT = "FIPS204-ACVP-PHASE-3-4"
DEFAULT_TESTS_PER_GROUP = 2
MAX_TESTS_PER_GROUP = 10
SEED_BYTES = 32
RND_BYTES = 32
MU_BYTES = 64
DEFAULT_MESSAGE_BITS = 128
DEFAULT_CONTEXT_BITS = 0
MAX_CONTEXT_BYTES = 255


def derive_hex(seed_material: str, label: str, nbytes: int) -> str:
    chunks: List[bytes] = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < nbytes:
        hasher = hashlib.sha256()
        hasher.update(str(seed_material).encode("utf-8"))
        hasher.update(b"|")
        hasher.update(label.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(str(counter).encode("ascii"))
        chunks.append(hasher.digest())
        counter += 1
    return b"".join(chunks)[:nbytes].hex().upper()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fallback_campaign_seed(registration_container: Dict[str, Any]) -> str:
    return hashlib.sha256(
        (canonical_json(registration_container) + FALLBACK_CAMPAIGN_SEED_SALT).encode(
            "utf-8"
        )
    ).hexdigest().upper()


def sample_length_from_domain(
    domain_list: List[Dict[str, int]],
    *,
    fallback_bits: int,
    label: str,
) -> int:
    if not domain_list:
        return max(0, fallback_bits)

    domain = domain_list[0]
    minimum = int(domain["min"])
    maximum = int(domain["max"])
    increment = int(domain["increment"])

    target = fallback_bits
    if label == "message" and target == 0 and maximum >= increment:
        target = increment
    target = min(max(target, minimum), maximum)
    if increment > 0 and target % increment != 0:
        target = ((target + increment - 1) // increment) * increment
        if target > maximum:
            target = maximum - (maximum % increment)
    if label == "message" and target == 0 and maximum >= increment:
        target = increment
    if label == "context":
        target = min(target, MAX_CONTEXT_BYTES * 8)
    return max(minimum, target)


def mutate_hex(value: str) -> str:
    if not value:
        return "00"
    first = "0" if value[0].upper() != "0" else "1"
    return first + value[1:]


def generate_vector_sets_from_negotiated_capabilities(
    negotiated_capabilities: Dict[str, Any],
    *,
    campaign_seed: str,
    tests_per_group: int = DEFAULT_TESTS_PER_GROUP,
) -> List[Dict[str, Any]]:
    vector_sets: List[Dict[str, Any]] = []
    vs_id = 1
    for entry in negotiated_capabilities.get("negotiated", []):
        mode = entry.get("mode")
        if mode == "keyGen":
            vector_sets.append(_build_keygen_vector_set(entry, campaign_seed, vs_id, tests_per_group))
        elif mode == "sigGen":
            vector_sets.append(_build_siggen_vector_set(entry, campaign_seed, vs_id, tests_per_group))
        elif mode == "sigVer":
            vector_sets.append(_build_sigver_vector_set(entry, campaign_seed, vs_id, tests_per_group))
        else:
            continue
        vs_id += 1
    return vector_sets


def _build_keygen_vector_set(
    entry: Dict[str, Any],
    campaign_seed: str,
    vs_id: int,
    tests_per_group: int,
) -> Dict[str, Any]:
    tg_id = 1
    tc_id = 1
    groups: List[Dict[str, Any]] = []
    for parameter_set in entry.get("parameterSets", []):
        tests = []
        for index in range(tests_per_group):
            tests.append(
                {
                    "tcId": tc_id,
                    "seed": derive_hex(
                        campaign_seed,
                        f"keyGen/vs{vs_id}/tg{tg_id}/tc{tc_id}/seed/{parameter_set}/{index}",
                        SEED_BYTES,
                    ),
                }
            )
            tc_id += 1
        groups.append(
            {
                "tgId": tg_id,
                "testType": "AFT",
                "parameterSet": parameter_set,
                "tests": tests,
            }
        )
        tg_id += 1
    return _vector_set(vs_id, "keyGen", groups)


def _build_siggen_vector_set(
    entry: Dict[str, Any],
    campaign_seed: str,
    vs_id: int,
    tests_per_group: int,
) -> Dict[str, Any]:
    groups: List[Dict[str, Any]] = []
    tg_id = 1
    tc_id = 1
    for capability in entry.get("capabilities", []):
        for parameter_set in capability.get("parameterSets", []):
            for signature_interface in entry.get("signatureInterfaces", []):
                if signature_interface == "internal":
                    for external_mu in entry.get("externalMu", []):
                        for deterministic in entry.get("deterministic", []):
                            group, tc_id = _siggen_internal_group(
                                campaign_seed,
                                vs_id,
                                tg_id,
                                tc_id,
                                tests_per_group,
                                parameter_set,
                                deterministic,
                                external_mu,
                                capability,
                            )
                            groups.append(group)
                            tg_id += 1
                elif signature_interface == "external":
                    for pre_hash in entry.get("preHash", []):
                        hash_algs = capability.get("hashAlgs", [None])
                        if pre_hash == "pure":
                            hash_algs = [None]
                        for hash_alg in hash_algs:
                            if pre_hash == "preHash" and hash_alg is None:
                                continue
                            for deterministic in entry.get("deterministic", []):
                                group, tc_id = _siggen_external_group(
                                    campaign_seed,
                                    vs_id,
                                    tg_id,
                                    tc_id,
                                    tests_per_group,
                                    parameter_set,
                                    deterministic,
                                    pre_hash,
                                    hash_alg,
                                    capability,
                                )
                                groups.append(group)
                                tg_id += 1
    return _vector_set(vs_id, "sigGen", groups)


def _build_sigver_vector_set(
    entry: Dict[str, Any],
    campaign_seed: str,
    vs_id: int,
    tests_per_group: int,
) -> Dict[str, Any]:
    groups: List[Dict[str, Any]] = []
    tg_id = 1
    tc_id = 1
    group_tests = max(2, tests_per_group)
    for capability in entry.get("capabilities", []):
        for parameter_set in capability.get("parameterSets", []):
            for signature_interface in entry.get("signatureInterfaces", []):
                if signature_interface == "internal":
                    for external_mu in entry.get("externalMu", []):
                        group, tc_id = _sigver_internal_group(
                            campaign_seed,
                            vs_id,
                            tg_id,
                            tc_id,
                            group_tests,
                            parameter_set,
                            external_mu,
                            capability,
                        )
                        groups.append(group)
                        tg_id += 1
                elif signature_interface == "external":
                    for pre_hash in entry.get("preHash", []):
                        hash_algs = capability.get("hashAlgs", [None])
                        if pre_hash == "pure":
                            hash_algs = [None]
                        for hash_alg in hash_algs:
                            if pre_hash == "preHash" and hash_alg is None:
                                continue
                            group, tc_id = _sigver_external_group(
                                campaign_seed,
                                vs_id,
                                tg_id,
                                tc_id,
                                group_tests,
                                parameter_set,
                                pre_hash,
                                hash_alg,
                                capability,
                            )
                            groups.append(group)
                            tg_id += 1
    return _vector_set(vs_id, "sigVer", groups)


def _siggen_internal_group(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    tests_per_group: int,
    parameter_set: str,
    deterministic: bool,
    external_mu: bool,
    capability: Dict[str, Any],
) -> tuple[Dict[str, Any], int]:
    tests = []
    for index in range(tests_per_group):
        test_seed = _test_seed(campaign_seed, vs_id, tg_id, tc_id, parameter_set, index)
        keypair = keygen_internal(parameter_set, test_seed)
        test: Dict[str, Any] = {"tcId": tc_id, "sk": keypair["sk"]}
        if external_mu:
            test["mu"] = derive_hex(campaign_seed, f"sigGen/tc{tc_id}/mu", MU_BYTES)
        else:
            message_bytes = _message_bytes(capability)
            test["message"] = derive_hex(campaign_seed, f"sigGen/tc{tc_id}/message", message_bytes)
        if not deterministic:
            test["rnd"] = derive_hex(campaign_seed, f"sigGen/tc{tc_id}/rnd", RND_BYTES)
        tests.append(test)
        tc_id += 1
    return (
        {
            "tgId": tg_id,
            "testType": "AFT",
            "parameterSet": parameter_set,
            "deterministic": deterministic,
            "signatureInterface": "internal",
            "externalMu": external_mu,
            "tests": tests,
        },
        tc_id,
    )


def _siggen_external_group(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    tests_per_group: int,
    parameter_set: str,
    deterministic: bool,
    pre_hash: str,
    hash_alg: Optional[str],
    capability: Dict[str, Any],
) -> tuple[Dict[str, Any], int]:
    tests = []
    for index in range(tests_per_group):
        test_seed = _test_seed(campaign_seed, vs_id, tg_id, tc_id, parameter_set, index)
        keypair = keygen_internal(parameter_set, test_seed)
        test: Dict[str, Any] = {
            "tcId": tc_id,
            "sk": keypair["sk"],
            "message": derive_hex(campaign_seed, f"sigGen/tc{tc_id}/message", _message_bytes(capability)),
            "context": derive_hex(campaign_seed, f"sigGen/tc{tc_id}/context", _context_bytes(capability)),
        }
        if hash_alg is not None:
            test["hashAlg"] = hash_alg
        if not deterministic:
            test["rnd"] = derive_hex(campaign_seed, f"sigGen/tc{tc_id}/rnd", RND_BYTES)
        tests.append(test)
        tc_id += 1
    return (
        {
            "tgId": tg_id,
            "testType": "AFT",
            "parameterSet": parameter_set,
            "deterministic": deterministic,
            "signatureInterface": "external",
            "preHash": pre_hash,
            "tests": tests,
        },
        tc_id,
    )


def _sigver_internal_group(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    tests_per_group: int,
    parameter_set: str,
    external_mu: bool,
    capability: Dict[str, Any],
) -> tuple[Dict[str, Any], int]:
    tests = []
    for index in range(tests_per_group):
        test, tc_id = _sigver_internal_test(
            campaign_seed,
            vs_id,
            tg_id,
            tc_id,
            index,
            parameter_set,
            external_mu,
            capability,
            invalid=(index % 2 == 1),
        )
        tests.append(test)
    return (
        {
            "tgId": tg_id,
            "testType": "AFT",
            "parameterSet": parameter_set,
            "signatureInterface": "internal",
            "externalMu": external_mu,
            "tests": tests,
        },
        tc_id,
    )


def _sigver_external_group(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    tests_per_group: int,
    parameter_set: str,
    pre_hash: str,
    hash_alg: Optional[str],
    capability: Dict[str, Any],
) -> tuple[Dict[str, Any], int]:
    tests = []
    for index in range(tests_per_group):
        test, tc_id = _sigver_external_test(
            campaign_seed,
            vs_id,
            tg_id,
            tc_id,
            index,
            parameter_set,
            pre_hash,
            hash_alg,
            capability,
            invalid=(index % 2 == 1),
        )
        tests.append(test)
    return (
        {
            "tgId": tg_id,
            "testType": "AFT",
            "parameterSet": parameter_set,
            "signatureInterface": "external",
            "preHash": pre_hash,
            "tests": tests,
        },
        tc_id,
    )


def _sigver_internal_test(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    index: int,
    parameter_set: str,
    external_mu: bool,
    capability: Dict[str, Any],
    *,
    invalid: bool,
) -> tuple[Dict[str, Any], int]:
    keypair = keygen_internal(parameter_set, _test_seed(campaign_seed, vs_id, tg_id, tc_id, parameter_set, index))
    if external_mu:
        mu = derive_hex(campaign_seed, f"sigVer/tc{tc_id}/mu", MU_BYTES)
        signature = siggen_internal(
            parameter_set,
            keypair["sk"],
            None,
            mu_hex=mu,
            external_mu=True,
            deterministic=True,
            signature_interface="internal",
        )["signature"]
        test = {"tcId": tc_id, "pk": keypair["pk"], "mu": mu, "signature": signature}
        if invalid:
            test["mu"] = mutate_hex(mu)
    else:
        message = derive_hex(campaign_seed, f"sigVer/tc{tc_id}/message", _message_bytes(capability))
        signature = siggen_internal(
            parameter_set,
            keypair["sk"],
            message,
            external_mu=False,
            deterministic=True,
            signature_interface="internal",
        )["signature"]
        test = {"tcId": tc_id, "pk": keypair["pk"], "message": message, "signature": signature}
        if invalid:
            test["message"] = mutate_hex(message)
    return test, tc_id + 1


def _sigver_external_test(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    index: int,
    parameter_set: str,
    pre_hash: str,
    hash_alg: Optional[str],
    capability: Dict[str, Any],
    *,
    invalid: bool,
) -> tuple[Dict[str, Any], int]:
    keypair = keygen_internal(parameter_set, _test_seed(campaign_seed, vs_id, tg_id, tc_id, parameter_set, index))
    message = derive_hex(campaign_seed, f"sigVer/tc{tc_id}/message", _message_bytes(capability))
    context = derive_hex(campaign_seed, f"sigVer/tc{tc_id}/context", _context_bytes(capability))
    signature = siggen_internal(
        parameter_set,
        keypair["sk"],
        message,
        external_mu=False,
        deterministic=True,
        signature_interface="external",
        pre_hash=pre_hash,
        context_hex=context,
        hash_alg=hash_alg,
    )["signature"]
    test: Dict[str, Any] = {
        "tcId": tc_id,
        "pk": keypair["pk"],
        "message": message,
        "context": context,
        "signature": signature,
    }
    if hash_alg is not None:
        test["hashAlg"] = hash_alg
    if invalid:
        test["message"] = mutate_hex(message)
    return test, tc_id + 1


def _vector_set(vs_id: int, mode: str, groups: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "vsId": vs_id,
        "algorithm": ALGORITHM,
        "mode": mode,
        "revision": REVISION,
        "isSample": True,
        "testGroups": groups,
    }


def _test_seed(
    campaign_seed: str,
    vs_id: int,
    tg_id: int,
    tc_id: int,
    parameter_set: str,
    index: int,
) -> str:
    return derive_hex(
        campaign_seed,
        f"keypair/vs{vs_id}/tg{tg_id}/tc{tc_id}/{parameter_set}/{index}",
        int(SUPPORTED_PARAMETER_SETS[parameter_set]["seed_bytes"]),
    )


def _message_bytes(capability: Dict[str, Any]) -> int:
    bits = sample_length_from_domain(
        capability.get("messageLength", []),
        fallback_bits=DEFAULT_MESSAGE_BITS,
        label="message",
    )
    return max(1, bits // 8)


def _context_bytes(capability: Dict[str, Any]) -> int:
    bits = sample_length_from_domain(
        capability.get("contextLength", []),
        fallback_bits=DEFAULT_CONTEXT_BITS,
        label="context",
    )
    return min(MAX_CONTEXT_BYTES, max(0, bits // 8))
