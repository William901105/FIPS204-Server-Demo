from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


_BACKEND_DIR = Path(__file__).resolve().parents[2]
MLDSA_NATIVE_ORACLE_DIR = _BACKEND_DIR / "native" / "mldsa_oracle"

SUPPORTED_PARAMETER_SETS: Dict[str, Dict[str, Any]] = {
    "ML-DSA-44": {
        "level": 44,
        "pk_bytes": 1312,
        "sk_bytes": 2560,
        "sig_bytes": 2420,
        "seed_bytes": 32,
        "rnd_bytes": 32,
        "mu_bytes": 64,
        "keygen_binary": MLDSA_NATIVE_ORACLE_DIR / "bin" / "mldsa44_keygen_oracle",
        "siggen_binary": MLDSA_NATIVE_ORACLE_DIR / "bin" / "mldsa44_siggen_oracle",
    },
    "ML-DSA-65": {
        "level": 65,
        "pk_bytes": 1952,
        "sk_bytes": 4032,
        "sig_bytes": 3309,
        "seed_bytes": 32,
        "rnd_bytes": 32,
        "mu_bytes": 64,
        "keygen_binary": MLDSA_NATIVE_ORACLE_DIR / "bin" / "mldsa65_keygen_oracle",
        "siggen_binary": MLDSA_NATIVE_ORACLE_DIR / "bin" / "mldsa65_siggen_oracle",
    },
    "ML-DSA-87": {
        "level": 87,
        "pk_bytes": 2592,
        "sk_bytes": 4896,
        "sig_bytes": 4627,
        "seed_bytes": 32,
        "rnd_bytes": 32,
        "mu_bytes": 64,
        "keygen_binary": MLDSA_NATIVE_ORACLE_DIR / "bin" / "mldsa87_keygen_oracle",
        "siggen_binary": MLDSA_NATIVE_ORACLE_DIR / "bin" / "mldsa87_siggen_oracle",
    },
}
