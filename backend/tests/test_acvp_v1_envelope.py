from __future__ import annotations

import json
from typing import Any, Dict

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.envelope import (
    acvp_envelope,
    envelope_response,
    with_local_metadata,
)
from app.acvp_protocol.routes import get_acvp_v1_algorithms, get_acvp_v1_version
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_acvp_envelope_wraps_body_with_version_header() -> None:
    assert acvp_envelope({"x": 1}) == [{"acvVersion": "1.0"}, {"x": 1}]


def test_with_local_metadata_moves_flags_under_extensions() -> None:
    body = with_local_metadata(
        {
            "x": 1,
            "productionReady": False,
            "profile": "local-fips204-skeleton",
            "demoOnly": True,
            "notProductionAcvp": True,
        }
    )

    assert body["x"] == 1
    assert "productionReady" not in body
    assert body["extensions"]["localFips204Skeleton"] == {
        "productionReady": False,
        "profile": "local-fips204-skeleton",
        "demoOnly": True,
        "notProductionAcvp": True,
    }


def test_envelope_response_can_include_local_metadata_extension() -> None:
    envelope = envelope_response({"x": 1}, include_local_metadata=True)

    assert envelope[0] == {"acvVersion": "1.0"}
    assert envelope[1]["x"] == 1
    assert envelope[1]["extensions"]["localFips204Skeleton"]["productionReady"] is False
    assert "productionReady" not in envelope[1]


def test_version_and_algorithms_routes_return_acvp_envelope() -> None:
    version = envelope_body(get_acvp_v1_version())
    algorithms = envelope_body(get_acvp_v1_algorithms())

    assert version["apiVersion"] == "v1"
    assert version["extensions"]["localFips204Skeleton"]["productionReady"] is False
    assert "productionReady" not in version
    assert algorithms["algorithms"][0]["algorithm"] == "ML-DSA"
    assert algorithms["extensions"]["localFips204Skeleton"]["profile"] == "local-fips204-skeleton"


def envelope_body(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        value = json.loads(value.body.decode("utf-8"))
    assert isinstance(value, list)
    assert value[0] == {"acvVersion": "1.0"}
    assert isinstance(value[1], dict)
    return value[1]
