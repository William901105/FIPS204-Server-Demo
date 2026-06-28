from __future__ import annotations

import hashlib
import json
from itertools import cycle, islice
from typing import Any, Dict, Iterable, List, Optional

from ..acvp_mldsa.constants import ALGORITHM, REVISION
from ..crypto_oracle.mldsa_constants import SUPPORTED_PARAMETER_SETS
from ..crypto_oracle.mldsa_oracle import keygen_internal, siggen_internal


LOCAL_DEBUG_PROFILE = "local-debug"
NIST_CONFORMANCE_PROFILE = "nist-conformance"
GENERATION_PROFILES = {LOCAL_DEBUG_PROFILE, NIST_CONFORMANCE_PROFILE}
GENERATION_PROFILE = LOCAL_DEBUG_PROFILE
FALLBACK_CAMPAIGN_SEED_SALT = "FIPS204-ACVP-PHASE-3-4"
DEFAULT_TESTS_PER_GROUP = 2
MAX_TESTS_PER_GROUP = 10
NIST_KEYGEN_TESTS_PER_GROUP = 25
NIST_SIGGEN_TESTS_PER_GROUP = 15
NIST_SIGVER_TESTS_PER_GROUP = 15
NIST_SIGGEN_REJECTION_OUTCOME_TESTS = 5
NIST_SIGGEN_TOTAL_REJECTION_TESTS = 5
SEED_BYTES = 32
RND_BYTES = 32
MU_BYTES = 64
DEFAULT_MESSAGE_BITS = 128
DEFAULT_CONTEXT_BITS = 0
MAX_CONTEXT_BYTES = 255

SIGVER_MODIFICATION_VALID = "valid"
SIGVER_MODIFICATION_MESSAGE = "modified-message"
SIGVER_MODIFICATION_COMMITMENT = "modified-signature-commitment"
SIGVER_MODIFICATION_Z = "modified-signature-z"
SIGVER_MODIFICATION_HINT = "modified-signature-hint"
SIGVER_MODIFICATION_CLASSES = [
    SIGVER_MODIFICATION_VALID,
    SIGVER_MODIFICATION_MESSAGE,
    SIGVER_MODIFICATION_COMMITMENT,
    SIGVER_MODIFICATION_Z,
    SIGVER_MODIFICATION_HINT,
]
SIGVER_CONFORMANCE_MODIFICATION_SEQUENCE = [
    modification
    for modification in SIGVER_MODIFICATION_CLASSES
    for _ in range(3)
]

MLDSA_SIGNATURE_LAYOUT = {
    "ML-DSA-44": {
        "commitment": (0, 32),
        "z": (32, 4 * 576),
        "hint": (32 + (4 * 576), 80 + 4),
    },
    "ML-DSA-65": {
        "commitment": (0, 48),
        "z": (48, 5 * 640),
        "hint": (48 + (5 * 640), 55 + 6),
    },
    "ML-DSA-87": {
        "commitment": (0, 64),
        "z": (64, 7 * 640),
        "hint": (64 + (7 * 640), 75 + 8),
    },
}


def _hex(value: str) -> str:
    return "".join(value.split()).upper()


SIGGEN_REJECTION_OUTCOME_KATS = [
    {
        "parameterSet": "ML-DSA-44",
        "seed": _hex("5C624FCC 18624524 52D0C665 840D8237 F43108E5 499EDCDC 108FBC49 D596E4B7"),
        "message": _hex("951FDF54 73A4CBA6 D9E5B5DB 7E79FB81 73921BA5 B13E9271 401B8F90 7B8B7D5B"),
    },
    {
        "parameterSet": "ML-DSA-44",
        "seed": _hex("836EABED B4D2CD9B E6A4D957 CF5EE6BF 48930413 6864C55C 2C5F01DA 5047D18B"),
        "message": _hex("199A0AB7 35E90041 63DD02D3 19A61CFE 81638E3B F47BB1E9 0E90D6E3 EA545247"),
    },
    {
        "parameterSet": "ML-DSA-44",
        "seed": _hex("CA5A01E1 EA6552CB 5C980346 2B94C2F1 DC9D13BB 17A6ACE5 10D15705 6A2C6114"),
        "message": _hex("8C8CACA8 8FFF52B9 33051053 7B3701B3 993F3726 136A650F 48F86045 51550832"),
    },
    {
        "parameterSet": "ML-DSA-44",
        "seed": _hex("9C005F15 50B4F318 55C6B92F 97873673 3F37791C B39DD182 D7BA5732 BDC2483E"),
        "message": _hex("B744343F 30F7FEE0 88998BA5 74E799F1 BF3939C0 6C29BF9A C10F3588 A57E21E2"),
    },
    {
        "parameterSet": "ML-DSA-44",
        "seed": _hex("4FAB5485 B009399E 8AE6FC3D 3EEFBFE8 E09796E4 477AABD5 EB1CC908 FA734DE3"),
        "message": _hex("7CAB0FDC F4BEA5F0 39137478 AA45C9C4 8EF96D90 6FC49F6E 2F138111 BF1B4A4E"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "seed": _hex("464756A9 85E5DF03 739D95DD 309C1ED9 C5B04254 CC294E7E 7EB9B936 5EE15117"),
        "message": _hex("491101BB A044DE6E 44A63796 C33CDA05 1BB05A60 725B87AF 4BA9DB94 0C03AC09"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "seed": _hex("235A48DB 4CA7916B 884F424A 8586EFD5 17E87C64 AECEC0FC E9A3CC21 2BA1522E"),
        "message": _hex("F8CE85CB 2EC474FF BF5A3FFA E029CE6F 4526B8D5 97655067 F97F438B 81071E9B"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "seed": _hex("E13131B7 05A76030 5FEFFEBF E99082E2 691A444B BEFCC3ED F67D9098 86200207"),
        "message": _hex("CD365512 C7E61BBA A130800B 37F3BB46 AAF1BEEF 3742EA8A 9010A6DD 4576ED0B"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "seed": _hex("0A4793E0 40A4BC0D 0F37643D 12C1EA1F 10648724 609936C7 6E0EC83E 37209E92"),
        "message": _hex("6D9C7A79 5E48D80A 892CBF4D 45584297 87277E38 06EB5D0B CE1640EE BBBF9AEC"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "seed": _hex("F865B889 E5022D54 BABC81CA 67E7EB39 F1AC42F9 2CF5295C 3DA5C966 7DB1B924"),
        "message": _hex("047AFAAD BE020ED2 D766DA85 317DEDE8 0BE55054 5F0B21E3 F555A990 F8004258"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "seed": _hex("0D582191 32746BE0 77DFE821 E9F8FD87 857B28AB 91D6A567 E312A73E 2636032C"),
        "message": _hex("3AA49EF7 2D010AEC 19383BA1 E83EC2DD 3DCC207A 96FFCEB9 FFA269E3 E3D66400"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "seed": _hex("146C47AB 9F88408E B76A8132 94D533B2 9D7E0FDA 75DA5A4E 7C69EB61 EFEEBB78"),
        "message": _hex("82C44F99 8A8D24F0 56084D0E 80ECFD84 34493385 A284C699 74923C27 0D397782"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "seed": _hex("049D9B0B 646A2AC7 F50B63CE 5E4BFE44 C9B87634 F4FF6C14 C513E388 B8A1F808"),
        "message": _hex("FEBC9F8A E159002B E1A11D39 5959DD7F C2071813 5690CDAA 2BCFB580 1C02AB89"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "seed": _hex("9823DDDE 446A8EA8 83DAD3AC 6477F798 39FDC2D2 DEF2416B E0A8B71C FBC3F5C6"),
        "message": _hex("F7592C97 C1A96A2F 4053588F 5CDAD4C5 0BF7C375 2709854F A27779B4 45DD2BA2"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "seed": _hex("AE213FE8 589B414F 53780D8B 9B683717 9967E13C B474C5AD 365C0437 78D2BC90"),
        "message": _hex("19C1913B A76FF045 96BB7CC8 0FD825A5 AEDEF5D5 AD61CEDB 5203E6D7 EDB18877"),
    },
]

SIGGEN_TOTAL_REJECTION_KATS = [
    {
        "parameterSet": "ML-DSA-44",
        "rejectionCount": 77,
        "seed": _hex("090D97C1 F4166EB3 2CA67C5F B564ACBE 0735DB4A F4B8DB3A 7C2CE740 2357CA44"),
        "message": _hex("E3838364 B37F47ED FCA2B577 B20B80C3 CB51B9F5 6E0E4CDB 7DF002C8 74039252"),
    },
    {
        "parameterSet": "ML-DSA-44",
        "rejectionCount": 100,
        "seed": _hex("CFC73D07 A883543A 804F7700 70861825 143A62F2 F97D05FC E00FD8B2 5D29A43F"),
        "message": _hex("0960C13E 9BA467A9 38450120 CC96FF6F 04B7E557 C99A8386 19A48F9A 38738AB8"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "rejectionCount": 64,
        "seed": _hex("26B605C7 8AC762FA 1634C6F9 1DD117C4 FBFF7F3A 7E7781F0 CC83B628 1F04AD7F"),
        "message": _hex("C9B07E7D DC027446 8F312F5C 692A54AC 73D1E34D 8638E20A 2CD3C788 F27D4355"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "rejectionCount": 73,
        "seed": _hex("9191CF38 1BEE1747 5C011986 EFB6AFB1 EFA69974 42FD3342 7353F1DA 1AA39FC0"),
        "message": _hex("E616E36E 81AA1EC3 92621094 21AE0DDD A5E3B5A8 F4A252BC A27AE882 538DF618"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "rejectionCount": 66,
        "seed": _hex("516912C7 B90A3DBE 009B7478 DBCAF0F5 C5C9ED96 99A20D0C A56CC516 E5A444CD"),
        "message": _hex("9247CA75 F9456226 A0C783DA BCC33FF5 B4B48957 5ADED543 E74B29B4 5F9C8EF2"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "rejectionCount": 65,
        "seed": _hex("D4B841F8 82D50AB9 E590066B AFABA0F0 D04D3264 1C0B978E 54CCAA69 A6E8D2C4"),
        "message": _hex("17523165 7B0F3C70 65947999 467C3420 64F29BFA EB553E97 561407D5 560E3AEB"),
    },
    {
        "parameterSet": "ML-DSA-65",
        "rejectionCount": 64,
        "seed": _hex("5492EB8D 811072C0 30A30CC6 6B23A173 059EBA0D 4868CCB9 2FBE2510 B4A5915F"),
        "message": _hex("33D2753E D87D0003 B44C1AF5 F72EB931 F559C6B4 931AF7E2 49F65D3F A7613295"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "rejectionCount": 64,
        "seed": _hex("B5C07ECE FE9E7C3B 885FDEF0 32BDF9F8 07B4011E 2DFE6806 C088D208 1631C8EB"),
        "message": _hex("D1D5C2D1 67D6E629 06790A5F EDF5A0A7 54CFAF47 E6A11AEB 93FB8C41 934C31F8"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "rejectionCount": 65,
        "seed": _hex("E8FC3C9F AD711DDA 2946334F BBD33146 8D6E9AB4 8EB86DCD 03F300A1 7AEBC5E5"),
        "message": _hex("3B435F7A 2CE431C7 AB8EAE09 91C5DAC6 10827C99 D2780304 6FBC6C56 7D6B71F2"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "rejectionCount": 64,
        "seed": _hex("151F8088 6D6CE8C3 B428964F E02C40CA 0C8EFFA1 00EE089E 54D78534 4FCCF719"),
        "message": _hex("C628CE94 D2AA99AA 50CF15B1 47D4F9A9 C62A3D46 12152DE0 A502C377 F472D614"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "rejectionCount": 64,
        "seed": _hex("48BEFFB4 C97E59E4 74E1906F 39888BE5 AE62F6A0 11C05EF6 A6B8D1E5 4F2171B7"),
        "message": _hex("D2756A8F B4E47F79 6AF704ED 0FC8C6E5 73D42DFA B443B329 F00F8DB2 FF12C465"),
    },
    {
        "parameterSet": "ML-DSA-87",
        "rejectionCount": 69,
        "seed": _hex("FE2DA9DD 93A077FC B6452AC8 8D0A5762 EB896BAA AC6CE7D0 1CB1370B A8322390"),
        "message": _hex("A86B29AD F2300D26 36E21D4A 350CD18E 55A25437 9C3659A7 A95D8734 CEC1F005"),
    },
]


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
    generation_profile: str = LOCAL_DEBUG_PROFILE,
) -> List[Dict[str, Any]]:
    _validate_generation_profile(generation_profile)
    vector_sets: List[Dict[str, Any]] = []
    vs_id = 1
    for entry in negotiated_capabilities.get("negotiated", []):
        mode = entry.get("mode")
        mode_tests_per_group = _tests_per_group_for_mode(mode, tests_per_group, generation_profile)
        if mode == "keyGen":
            vector_sets.append(_build_keygen_vector_set(entry, campaign_seed, vs_id, mode_tests_per_group))
        elif mode == "sigGen":
            vector_sets.append(
                _build_siggen_vector_set(
                    entry,
                    campaign_seed,
                    vs_id,
                    mode_tests_per_group,
                    generation_profile,
                )
            )
        elif mode == "sigVer":
            vector_sets.append(
                _build_sigver_vector_set(
                    entry,
                    campaign_seed,
                    vs_id,
                    mode_tests_per_group,
                    generation_profile,
                )
            )
        else:
            continue
        vs_id += 1
    return vector_sets


def _validate_generation_profile(generation_profile: str) -> None:
    if generation_profile not in GENERATION_PROFILES:
        raise ValueError(
            "generationProfile must be one of: "
            + ", ".join(sorted(GENERATION_PROFILES))
        )


def _tests_per_group_for_mode(
    mode: Any,
    tests_per_group: int,
    generation_profile: str,
) -> int:
    if generation_profile != NIST_CONFORMANCE_PROFILE:
        return tests_per_group
    if mode == "keyGen":
        return max(tests_per_group, NIST_KEYGEN_TESTS_PER_GROUP)
    if mode == "sigGen":
        return max(tests_per_group, NIST_SIGGEN_TESTS_PER_GROUP)
    if mode == "sigVer":
        return max(tests_per_group, NIST_SIGVER_TESTS_PER_GROUP)
    return tests_per_group


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
    generation_profile: str,
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
                                generation_profile,
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
    generation_profile: str,
) -> Dict[str, Any]:
    groups: List[Dict[str, Any]] = []
    tg_id = 1
    tc_id = 1
    group_tests = tests_per_group if generation_profile == NIST_CONFORMANCE_PROFILE else max(2, tests_per_group)
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
                            generation_profile,
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
                                generation_profile,
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
    generation_profile: str,
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
    if (
        generation_profile == NIST_CONFORMANCE_PROFILE
        and deterministic
        and not external_mu
    ):
        for kat in _siggen_rejection_kats(parameter_set):
            keypair = keygen_internal(parameter_set, kat["seed"])
            tests.append({"tcId": tc_id, "sk": keypair["sk"], "message": kat["message"]})
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
    generation_profile: str,
) -> tuple[Dict[str, Any], int]:
    tests = []
    modifications = _sigver_modifications_for_group(tests_per_group, generation_profile)
    for index, modification in enumerate(modifications):
        test, tc_id = _sigver_internal_test(
            campaign_seed,
            vs_id,
            tg_id,
            tc_id,
            index,
            parameter_set,
            external_mu,
            capability,
            modification=modification,
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
    generation_profile: str,
) -> tuple[Dict[str, Any], int]:
    tests = []
    modifications = _sigver_modifications_for_group(tests_per_group, generation_profile)
    for index, modification in enumerate(modifications):
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
            modification=modification,
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
    modification: str,
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
        if modification == SIGVER_MODIFICATION_MESSAGE:
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
        if modification == SIGVER_MODIFICATION_MESSAGE:
            test["message"] = mutate_hex(message)
    if modification in {
        SIGVER_MODIFICATION_COMMITMENT,
        SIGVER_MODIFICATION_Z,
        SIGVER_MODIFICATION_HINT,
    }:
        test["signature"] = mutate_signature(
            test["signature"],
            parameter_set,
            modification,
        )
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
    modification: str,
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
    if modification == SIGVER_MODIFICATION_MESSAGE:
        test["message"] = mutate_hex(message)
    elif modification in {
        SIGVER_MODIFICATION_COMMITMENT,
        SIGVER_MODIFICATION_Z,
        SIGVER_MODIFICATION_HINT,
    }:
        test["signature"] = mutate_signature(
            test["signature"],
            parameter_set,
            modification,
        )
    return test, tc_id + 1


def _sigver_modifications_for_group(
    tests_per_group: int,
    generation_profile: str,
) -> List[str]:
    if generation_profile != NIST_CONFORMANCE_PROFILE:
        return [
            SIGVER_MODIFICATION_VALID
            if index % 2 == 0
            else SIGVER_MODIFICATION_MESSAGE
            for index in range(tests_per_group)
        ]
    return list(islice(cycle(SIGVER_CONFORMANCE_MODIFICATION_SEQUENCE), tests_per_group))


def mutate_signature(signature: str, parameter_set: str, modification: str) -> str:
    layout = MLDSA_SIGNATURE_LAYOUT[parameter_set]
    if modification == SIGVER_MODIFICATION_COMMITMENT:
        offset, _ = layout["commitment"]
        return mutate_hex_byte(signature, offset)
    if modification == SIGVER_MODIFICATION_Z:
        offset, length = layout["z"]
        return mutate_hex_byte(signature, offset + (length // 2))
    if modification == SIGVER_MODIFICATION_HINT:
        offset, length = layout["hint"]
        return mutate_hex_byte(signature, offset + length - 1)
    return signature


def mutate_hex_byte(value: str, byte_offset: int) -> str:
    data = bytearray.fromhex(value)
    data[byte_offset] ^= 0x01
    return data.hex().upper()


def _siggen_rejection_kats(parameter_set: str) -> List[Dict[str, Any]]:
    return [
        *_kats_for_parameter_set(
            SIGGEN_REJECTION_OUTCOME_KATS,
            parameter_set,
            NIST_SIGGEN_REJECTION_OUTCOME_TESTS,
        ),
        *_kats_for_parameter_set(
            SIGGEN_TOTAL_REJECTION_KATS,
            parameter_set,
            NIST_SIGGEN_TOTAL_REJECTION_TESTS,
        ),
    ]


def _kats_for_parameter_set(
    table: Iterable[Dict[str, Any]],
    parameter_set: str,
    minimum: int,
) -> List[Dict[str, Any]]:
    entries = [
        entry
        for entry in table
        if entry["parameterSet"] == parameter_set
    ]
    if not entries:
        return []
    if len(entries) >= minimum:
        return entries[:minimum]
    return list(islice(cycle(entries), minimum))


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
