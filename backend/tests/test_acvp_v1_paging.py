from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest
from fastapi.responses import JSONResponse

from app.acvp_protocol.paging import DEFAULT_LIMIT, MAX_LIMIT
from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set,
    get_acvp_v1_test_session_vector_sets,
    list_acvp_v1_test_sessions,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_test_sessions_default_paging_returns_first_default_limit() -> None:
    create_prompt_sessions(3)

    body = envelope_body(list_acvp_v1_test_sessions())

    assert len(body["testSessions"]) == 3
    assert body["pagination"]["offset"] == 0
    assert body["pagination"]["limit"] == DEFAULT_LIMIT
    assert body["pagination"]["total"] >= 3
    assert body["pagination"]["returned"] == 3
    assert body["data"] == body["testSessions"]
    assert body["totalCount"] == body["pagination"]["total"]


def test_test_sessions_limit_and_offset_are_stable() -> None:
    create_prompt_sessions(3)
    all_sessions = envelope_body(list_acvp_v1_test_sessions())["testSessions"]

    body = envelope_body(list_acvp_v1_test_sessions(limit="1", offset="1"))

    assert len(body["testSessions"]) == 1
    assert body["testSessions"][0]["testSessionId"] == all_sessions[1]["testSessionId"]
    assert body["pagination"]["limit"] == 1
    assert body["pagination"]["offset"] == 1
    assert body["links"]["next"] is not None
    assert body["links"]["previous"] is not None


@pytest.mark.parametrize(
    ("parameter", "value", "kwargs"),
    [
        ("limit", "0", {"limit": "0"}),
        ("limit", "-1", {"limit": "-1"}),
        ("limit", "abc", {"limit": "abc"}),
        ("offset", "-1", {"offset": "-1"}),
        ("offset", "abc", {"offset": "abc"}),
        ("limit", str(MAX_LIMIT + 1), {"limit": str(MAX_LIMIT + 1)}),
    ],
)
def test_test_sessions_invalid_paging_query_returns_normalized_error(
    parameter: str,
    value: str,
    kwargs: Dict[str, str],
) -> None:
    response = list_acvp_v1_test_sessions(**kwargs)

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = envelope_body(response)
    assert body["error"]["code"] == "INVALID_QUERY_PARAMETER"
    assert body["error"]["path"] == f"$.{parameter}"
    assert body["error"]["requestId"]
    assert body["error"]["details"]["parameter"] == parameter
    assert body["error"]["details"]["value"] == value


def test_test_sessions_status_filter_works_with_paging() -> None:
    create_prompt_sessions(2)
    created = envelope_body(
        create_acvp_v1_test_session(
            {
                "algorithms": [keygen_registration()],
                "campaignSeed": CAMPAIGN_SEED,
                "autoGenerateVectorSets": False,
            }
        )
    )

    body = envelope_body(
        list_acvp_v1_test_sessions(status="capabilitiesAccepted", limit="1", offset="0")
    )

    assert body["pagination"]["total"] == 1
    assert body["testSessions"][0]["testSessionId"] == created["testSessionId"]
    assert body["testSessions"][0]["status"] == "capabilitiesAccepted"


def test_unknown_test_session_status_filter_returns_400() -> None:
    response = list_acvp_v1_test_sessions(status="unknown")

    assert isinstance(response, JSONResponse)
    body = envelope_body(response)
    assert response.status_code == 400
    assert body["error"]["code"] == "INVALID_QUERY_PARAMETER"
    assert body["error"]["path"] == "$.status"


def test_vector_sets_listing_supports_paging() -> None:
    created = create_registration_session_with_three_vector_sets()

    body = envelope_body(
        get_acvp_v1_test_session_vector_sets(
            created["testSessionId"],
            limit="1",
            offset="0",
        )
    )

    assert body["testSessionId"] == created["testSessionId"]
    assert len(body["vectorSetUrls"]) == 1
    assert len(body["vectorSets"]) == 1
    assert body["vectorSetUrls"][0] == body["vectorSets"][0]["url"]
    assert body["pagination"]["limit"] == 1
    assert body["pagination"]["offset"] == 0
    assert body["pagination"]["total"] == 3
    assert body["data"] == body["vectorSetUrls"]


def test_vector_sets_status_filter_works_with_paging() -> None:
    created = create_registration_session_with_three_vector_sets()
    session_id = created["testSessionId"]
    downloaded_id = created["vectorSetIds"][0]

    envelope_body(get_acvp_v1_test_session_vector_set(session_id, downloaded_id))
    body = envelope_body(
        get_acvp_v1_test_session_vector_sets(
            session_id,
            status="downloaded",
            limit="10",
            offset="0",
        )
    )

    assert body["pagination"]["total"] == 1
    assert body["vectorSets"][0]["vectorSetId"] == downloaded_id
    assert body["vectorSets"][0]["status"] == "downloaded"


def test_vector_sets_invalid_query_returns_normalized_error() -> None:
    created = create_registration_session_with_three_vector_sets()

    response = get_acvp_v1_test_session_vector_sets(
        created["testSessionId"],
        limit="abc",
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = envelope_body(response)
    assert body["error"]["code"] == "INVALID_QUERY_PARAMETER"
    assert body["error"]["requestId"]


def create_prompt_sessions(count: int) -> List[Dict[str, Any]]:
    return [
        envelope_body(
            create_acvp_v1_test_session(
                {
                    "prompt": keygen_prompt(vs_id=43300 + index),
                    "label": f"phase 4-3 commit3 paging {index}",
                    "autoGenerateExpectedResults": True,
                }
            )
        )
        for index in range(count)
    ]


def create_registration_session_with_three_vector_sets() -> Dict[str, Any]:
    return envelope_body(
        create_acvp_v1_test_session(
            {
                "algorithms": full_registration(),
                "campaignSeed": CAMPAIGN_SEED,
                "testsPerGroup": 1,
            }
        )
    )


def envelope_body(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        value = json.loads(value.body.decode("utf-8"))
    assert isinstance(value, list)
    assert value[0] == {"acvVersion": "1.0"}
    assert isinstance(value[1], dict)
    return value[1]


def full_registration() -> List[Dict[str, Any]]:
    return [
        keygen_registration(),
        siggen_registration(["internal"]),
        sigver_registration(["internal"]),
    ]


def keygen_registration() -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "parameterSets": ["ML-DSA-44"],
    }


def siggen_registration(signature_interfaces: List[str]) -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "sigGen",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "deterministic": [True],
        "signatureInterfaces": signature_interfaces,
        "externalMu": [False],
        "capabilities": [capability()],
    }


def sigver_registration(signature_interfaces: List[str]) -> Dict[str, Any]:
    return {
        "algorithm": "ML-DSA",
        "mode": "sigVer",
        "revision": "FIPS204",
        "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
        "signatureInterfaces": signature_interfaces,
        "externalMu": [False],
        "capabilities": [capability()],
    }


def capability() -> Dict[str, List[Any]]:
    return {
        "parameterSets": ["ML-DSA-44"],
        "messageLength": [{"min": 8, "max": 128, "increment": 8}],
        "contextLength": [{"min": 0, "max": 64, "increment": 8}],
        "hashAlgs": ["SHA2-256"],
    }


def keygen_prompt(*, vs_id: int) -> Dict[str, Any]:
    return {
        "vsId": vs_id,
        "algorithm": "ML-DSA",
        "mode": "keyGen",
        "revision": "FIPS204",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "tests": [{"tcId": 1, "seed": SEED_32_BYTES}],
            }
        ],
    }
