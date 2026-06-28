from __future__ import annotations

import asyncio
import json
from typing import Any, Dict
from uuid import UUID

import pytest
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from app.acvp_protocol.routes import (
    create_acvp_v1_test_session,
    get_acvp_v1_test_session_vector_set_expected,
    get_acvp_v1_test_session_vector_set,
    get_acvp_v1_test_session_vector_sets,
    list_acvp_v1_test_sessions,
    submit_acvp_v1_test_session_vector_set_results,
)
from app.acvp_protocol.service import (
    ACVP_SKELETON_SESSION_STORE,
    ACVP_SKELETON_VECTOR_SET_STORE,
)
from app.main import (
    acvp_http_exception_handler,
    acvp_request_id_middleware,
    acvp_unhandled_exception_handler,
    health,
    import_generated_mldsa_bundle_and_validate,
    mldsa_expected_results,
)
from app.models import GeneratedMldsaImportRequest, MldsaExpectedResultsRequest


SEED_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"


@pytest.fixture(autouse=True)
def clear_acvp_v1_skeleton_stores() -> None:
    ACVP_SKELETON_SESSION_STORE.clear()
    ACVP_SKELETON_VECTOR_SET_STORE.clear()


def test_success_response_propagates_x_request_id() -> None:
    response = middleware_response(
        "/acvp/v1/version",
        headers={"X-Request-ID": "phase43c3-version"},
        call_next=lambda: JSONResponse(content=[{"acvVersion": "1.0"}, {"ok": True}]),
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "phase43c3-version"
    assert json.loads(response.body.decode("utf-8"))[0] == {"acvVersion": "1.0"}


def test_invalid_query_error_is_enveloped_and_propagates_x_request_id() -> None:
    response = middleware_response(
        "/acvp/v1/testSessions?limit=abc",
        headers={"X-Request-ID": "phase43c3-invalid-limit"},
        call_next=lambda: list_acvp_v1_test_sessions(limit="abc"),
    )
    body = envelope_body(response)

    assert response.status_code == 400
    assert response.headers["X-Request-ID"] == "phase43c3-invalid-limit"
    assert body["error"]["code"] == "INVALID_QUERY_PARAMETER"
    assert body["error"]["message"]
    assert body["error"]["path"] == "$.limit"
    assert body["error"]["requestId"] == "phase43c3-invalid-limit"
    assert "Traceback" not in response.body.decode("utf-8")


def test_error_without_x_request_id_generates_uuid_like_request_id() -> None:
    response = middleware_response(
        "/acvp/v1/testSessions?offset=-1",
        call_next=lambda: list_acvp_v1_test_sessions(offset="-1"),
    )
    body = envelope_body(response)

    assert response.status_code == 400
    assert response.headers["X-Request-ID"] == body["error"]["requestId"]
    UUID(body["error"]["requestId"])


def test_unknown_route_and_method_not_allowed_are_enveloped() -> None:
    unknown = asyncio.run(
        acvp_http_exception_handler(
            make_request("/acvp/v1/not-a-route"),
            StarletteHTTPException(status_code=404, detail="Not Found"),
        )
    )
    method = asyncio.run(
        acvp_http_exception_handler(
            make_request("/acvp/v1/version"),
            StarletteHTTPException(status_code=405, detail="Method Not Allowed"),
        )
    )
    unknown_body = envelope_body(unknown)
    method_body = envelope_body(method)

    assert unknown.status_code == 404
    assert unknown_body["error"]["code"] == "UNKNOWN_ACVP_RESOURCE"
    assert unknown_body["error"]["requestId"]
    assert method.status_code == 405
    assert method_body["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert method_body["error"]["path"] == "/acvp/v1/version"


def test_unhandled_acvp_exception_is_500_envelope_without_stack_trace() -> None:
    response = asyncio.run(
        acvp_unhandled_exception_handler(
            make_request("/acvp/v1/version"),
            RuntimeError("sensitive internal failure"),
        )
    )
    body = envelope_body(response)
    text = response.body.decode("utf-8")

    assert response.status_code == 500
    assert body["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert body["error"]["message"] == "Internal server error."
    assert "sensitive internal failure" not in text
    assert "Traceback" not in text


def test_unknown_session_returns_normalized_404_envelope() -> None:
    response = middleware_response(
        "/acvp/v1/testSessions/not-a-session/vectorSets",
        headers={"X-Request-ID": "phase43c3-unknown-session"},
        call_next=lambda: get_acvp_v1_test_session_vector_sets("not-a-session"),
    )
    body = envelope_body(response)

    assert response.status_code == 404
    assert response.headers["X-Request-ID"] == "phase43c3-unknown-session"
    assert body["error"]["code"] == "UNKNOWN_TEST_SESSION"
    assert body["error"]["requestId"] == "phase43c3-unknown-session"


def test_unknown_vector_set_returns_normalized_404_envelope() -> None:
    created = envelope_body(
        create_acvp_v1_test_session(
            {
                "prompt": keygen_prompt(),
                "label": "phase 4-3 commit3 unknown vector set",
                "autoGenerateExpectedResults": True,
            }
        )
    )

    response = middleware_response(
        f"/acvp/v1/testSessions/{created['testSessionId']}/vectorSets/not-a-vector",
        call_next=lambda: get_acvp_v1_test_session_vector_set(
            created["testSessionId"],
            "not-a-vector",
        ),
    )
    body = envelope_body(response)

    assert response.status_code == 404
    assert body["error"]["code"] == "UNKNOWN_VECTOR_SET"
    assert body["error"]["requestId"]


def test_invalid_results_envelope_remains_normalized() -> None:
    session_id, vector_set_id, expected = create_session()

    response = submit_acvp_v1_test_session_vector_set_results(
        session_id,
        vector_set_id,
        [{"wrong": "1.0"}, expected],
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    body = envelope_body(response)
    assert body["error"]["code"] == "INVALID_ACVP_ENVELOPE"
    assert body["error"]["message"]
    assert body["error"]["path"] == "$[0].acvVersion"
    assert body["error"]["requestId"]


def test_api_endpoints_are_not_wrapped_in_acvp_envelope() -> None:
    health_response = health()
    expected = mldsa_expected_results(
        MldsaExpectedResultsRequest(prompt=keygen_prompt())
    )
    imported = import_generated_mldsa_bundle_and_validate(
        GeneratedMldsaImportRequest(
            prompt=keygen_prompt(),
            response=expected.expectedResults,
            label="phase43c3 api unaffected",
        )
    )

    assert health_response == {"status": "ok"}
    assert not isinstance(health_response, list)
    assert expected.expectedResults["mode"] == "keyGen"
    assert "validationResult" in imported
    assert not isinstance(imported, list)


def create_session() -> tuple[str, str, Dict[str, Any]]:
    created = envelope_body(
        create_acvp_v1_test_session(
            {
                "prompt": keygen_prompt(),
                "label": "phase 4-3 commit3 error test",
                "autoGenerateExpectedResults": True,
            }
        )
    )
    session_id = created["testSessionId"]
    vector_set_id = created["vectorSetIds"][0]
    expected = envelope_body(
        get_acvp_v1_test_session_vector_set_expected(session_id, vector_set_id)
    )["expectedResults"]
    return session_id, vector_set_id, expected


def envelope_body(value: Any) -> Dict[str, Any]:
    if isinstance(value, JSONResponse):
        value = json.loads(value.body.decode("utf-8"))
    assert isinstance(value, list)
    assert value[0] == {"acvVersion": "1.0"}
    assert isinstance(value[1], dict)
    return value[1]


def middleware_response(
    target: str,
    *,
    headers: Dict[str, str] = None,
    call_next,
) -> JSONResponse:
    request = make_request(target, headers=headers)

    async def wrapped_call_next(_request: Request) -> JSONResponse:
        return call_next()

    return asyncio.run(acvp_request_id_middleware(request, wrapped_call_next))


def make_request(
    target: str,
    *,
    method: str = "GET",
    headers: Dict[str, str] = None,
) -> Request:
    path, _, query = target.partition("?")
    normalized_headers = {
        "host": "testserver",
        **(headers or {}),
    }
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query.encode("utf-8"),
        "root_path": "",
        "headers": [
            (key.lower().encode("latin-1"), value.encode("latin-1"))
            for key, value in normalized_headers.items()
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def keygen_prompt() -> Dict[str, Any]:
    return {
        "vsId": 43311,
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
