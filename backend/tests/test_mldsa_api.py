from __future__ import annotations

import json
from pathlib import Path

from fastapi.responses import JSONResponse

from app.main import (
    import_bundle,
    validate_mldsa_registration_schema,
    validate_mldsa_vector_set_schema,
)
from app.models import ImportRequest


SAMPLE_ROOT = Path(__file__).resolve().parents[2] / "sample-data"


def test_schema_vector_set_endpoint_success() -> None:
    payload = json.loads((SAMPLE_ROOT / "ML-DSA-keyGen-FIPS204" / "prompt.json").read_text())

    response = validate_mldsa_vector_set_schema(payload)

    assert response["ok"] is True
    assert response["type"] == "vector-set"


def test_schema_registration_endpoint_error_is_structured() -> None:
    response = validate_mldsa_registration_schema(
        {
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS204",
            "parameterSets": ["ML-DSA-44"],
        },
    )

    assert isinstance(response, JSONResponse)
    body = json.loads(response.body)
    assert response.status_code == 400
    assert body["ok"] is False
    assert body["errorType"] == "schema"
    assert body["code"] == "unsupported_algorithm"


def test_import_flow_runs_schema_validation() -> None:
    sample_dir = SAMPLE_ROOT / "ML-DSA-keyGen-FIPS204"

    response = import_bundle(
        ImportRequest(
            prompt=json.loads((sample_dir / "prompt.json").read_text()),
            expectedResults=json.loads((sample_dir / "expectedResults.json").read_text()),
            response=json.loads((sample_dir / "response.pass.json").read_text()),
            label="schema test",
        )
    )

    assert response.mode == "keyGen"
