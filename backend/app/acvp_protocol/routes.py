from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ..models import (
    AcvpV1TestSessionCreateRequest,
    AcvpV1VectorSetGenerateRequest,
    AcvpV1VectorSetResultsSubmitRequest,
)
from .service import (
    acvp_skeleton_error,
    algorithms,
    cancel_vector_set,
    create_test_session,
    delete_test_session,
    generate_vector_sets_for_session,
    get_test_session,
    get_test_session_results,
    get_test_session_vector_sets,
    get_vector_set,
    get_vector_set_expected,
    get_vector_set_expected_results,
    get_vector_set_prompt,
    get_vector_set_results,
    list_test_sessions,
    submit_test_session_for_validation,
    submit_vector_set_results,
    version,
)
from .envelope import envelope_response


router = APIRouter(prefix="/acvp/v1", tags=["ACVP v1 skeleton"])


@router.get("/version")
def get_acvp_v1_version(
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        version(),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/algorithms")
def get_acvp_v1_algorithms(
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        algorithms(),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions")
def list_acvp_v1_test_sessions(
    status: Optional[str] = None,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        list_test_sessions(status=status),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions")
def create_acvp_v1_test_session(
    payload: Any = Body(...),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    request = _parse_session_create_request(payload)
    if isinstance(request, JSONResponse):
        return _canonical_response(
            request,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        create_test_session(request),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}")
def get_acvp_v1_test_session(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        get_test_session(sessionId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets")
def get_acvp_v1_test_session_vector_sets(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        get_test_session_vector_sets(sessionId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions/{sessionId}/vectorSets/generate")
def generate_acvp_v1_test_session_vector_sets(
    sessionId: str,
    payload: Any = Body(default=None),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    request = _parse_vector_set_generate_request(payload)
    if isinstance(request, JSONResponse):
        return _canonical_response(
            request,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        generate_vector_sets_for_session(sessionId, request),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets/{vectorSetId}")
def get_acvp_v1_test_session_vector_set(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        get_vector_set_prompt(sessionId, vectorSetId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.delete("/testSessions/{sessionId}/vectorSets/{vectorSetId}")
def delete_acvp_v1_test_session_vector_set(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        cancel_vector_set(sessionId, vectorSetId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions/{sessionId}/vectorSets/{vectorSetId}/results")
def submit_acvp_v1_test_session_vector_set_results(
    sessionId: str,
    vectorSetId: str,
    payload: Any = Body(...),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    request = _parse_results_submit_request(payload)
    if isinstance(request, JSONResponse):
        return _canonical_response(
            request,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        submit_vector_set_results(sessionId, vectorSetId, request.response),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.put("/testSessions/{sessionId}/vectorSets/{vectorSetId}/results")
def update_acvp_v1_test_session_vector_set_results(
    sessionId: str,
    vectorSetId: str,
    payload: Any = Body(...),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    request = _parse_results_submit_request(payload)
    if isinstance(request, JSONResponse):
        return _canonical_response(
            request,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        submit_vector_set_results(sessionId, vectorSetId, request.response, update=True),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets/{vectorSetId}/results")
def get_acvp_v1_test_session_vector_set_results(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        get_vector_set_results(sessionId, vectorSetId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets/{vectorSetId}/expected")
def get_acvp_v1_test_session_vector_set_expected(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        get_vector_set_expected(sessionId, vectorSetId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/results")
def get_acvp_v1_test_session_results(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        get_test_session_results(sessionId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions/{sessionId}/submit")
def submit_acvp_v1_test_session(
    sessionId: str,
    payload: Any = Body(default=None),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        submit_test_session_for_validation(sessionId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.delete("/testSessions/{sessionId}")
def delete_acvp_v1_test_session(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
) -> Any:
    return _canonical_response(
        delete_test_session(sessionId),
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/vectorSets/{vectorSetId}")
def get_acvp_v1_vector_set(vectorSetId: str) -> Any:
    return _compatibility_alias_response(get_vector_set(vectorSetId))


@router.delete("/vectorSets/{vectorSetId}")
def delete_acvp_v1_vector_set(vectorSetId: str) -> Any:
    return _compatibility_alias_response(cancel_vector_set(None, vectorSetId))


@router.post("/vectorSets/{vectorSetId}/results")
def submit_acvp_v1_vector_set_results(
    vectorSetId: str,
    payload: Any = Body(...),
) -> Any:
    request = _parse_results_submit_request(payload)
    if isinstance(request, JSONResponse):
        return _compatibility_alias_response(request)
    return _compatibility_alias_response(
        submit_vector_set_results(None, vectorSetId, request.response)
    )


@router.get("/vectorSets/{vectorSetId}/results")
def get_acvp_v1_vector_set_results(vectorSetId: str) -> Any:
    return _compatibility_alias_response(get_vector_set_results(None, vectorSetId))


@router.get("/vectorSets/{vectorSetId}/expectedResults")
def get_acvp_v1_vector_set_expected_results(vectorSetId: str) -> Any:
    return _compatibility_alias_response(get_vector_set_expected_results(vectorSetId))


def _canonical_response(
    value: Any,
    *,
    profile: Optional[str] = None,
    include_local_metadata: bool = False,
) -> Any:
    if profile == "debug" or include_local_metadata:
        return value
    if isinstance(value, JSONResponse):
        body = _json_response_body(value)
        return JSONResponse(
            status_code=value.status_code,
            content=envelope_response(body, include_local_metadata=True),
        )
    return envelope_response(value, include_local_metadata=True)


def _compatibility_alias_response(value: Any) -> Any:
    if isinstance(value, JSONResponse):
        body = _with_compatibility_alias(_json_response_body(value))
        return JSONResponse(status_code=value.status_code, content=body)
    return _with_compatibility_alias(value)


def _with_compatibility_alias(body: Any) -> Any:
    if not isinstance(body, dict):
        return body
    aliased = dict(body)
    aliased["localCompatibilityAlias"] = True
    return aliased


def _json_response_body(response: JSONResponse) -> Dict[str, Any]:
    content = json.loads(response.body.decode("utf-8"))
    if not isinstance(content, dict):
        return {"value": content}
    return content


def _parse_session_create_request(payload: Any) -> Any:
    if isinstance(payload, AcvpV1TestSessionCreateRequest):
        return payload
    if not isinstance(payload, dict):
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            "Request body must be a JSON object.",
            "$",
        )
    has_prompt = "prompt" in payload and payload.get("prompt") is not None
    has_algorithms = "algorithms" in payload and payload.get("algorithms") is not None
    if has_prompt and has_algorithms:
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            "prompt and algorithms cannot both be present in one test session request.",
            "$",
        )
    if not has_prompt and not has_algorithms:
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            "Request must include either prompt or algorithms.",
            "$",
        )
    try:
        return AcvpV1TestSessionCreateRequest.model_validate(payload)
    except ValidationError as exc:
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            _validation_error_message(exc),
            "$",
        )


def _parse_results_submit_request(payload: Any) -> Any:
    if isinstance(payload, AcvpV1VectorSetResultsSubmitRequest):
        return payload
    try:
        return AcvpV1VectorSetResultsSubmitRequest.model_validate(payload)
    except ValidationError as exc:
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            _validation_error_message(exc),
            "$.response",
        )


def _parse_vector_set_generate_request(payload: Any) -> Any:
    if isinstance(payload, AcvpV1VectorSetGenerateRequest):
        return payload
    if payload is None:
        payload = {}
    try:
        return AcvpV1VectorSetGenerateRequest.model_validate(payload)
    except ValidationError as exc:
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            _validation_error_message(exc),
            "$",
        )


def _validation_error_message(exc: ValidationError) -> str:
    errors = exc.errors(include_context=False)
    if not errors:
        return "Invalid request body."
    first = errors[0]
    location = ".".join(str(item) for item in first.get("loc", ()))
    if location:
        return f"{location}: {first.get('msg', 'Invalid request body.')}"
    return str(first.get("msg", "Invalid request body."))
