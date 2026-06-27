from __future__ import annotations

from typing import Any, Dict

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
    create_test_session,
    delete_test_session,
    generate_vector_sets_for_session,
    get_test_session,
    get_test_session_results,
    get_test_session_vector_sets,
    get_vector_set,
    get_vector_set_expected_results,
    get_vector_set_results,
    list_test_sessions,
    submit_vector_set_results,
    version,
)


router = APIRouter(prefix="/acvp/v1", tags=["ACVP v1 skeleton"])


@router.get("/version")
def get_acvp_v1_version() -> Dict[str, Any]:
    return version()


@router.get("/algorithms")
def get_acvp_v1_algorithms() -> Dict[str, Any]:
    return algorithms()


@router.get("/testSessions")
def list_acvp_v1_test_sessions() -> Dict[str, Any]:
    return list_test_sessions()


@router.post("/testSessions")
def create_acvp_v1_test_session(payload: Any = Body(...)) -> Any:
    request = _parse_session_create_request(payload)
    if isinstance(request, JSONResponse):
        return request
    return create_test_session(request)


@router.get("/testSessions/{sessionId}")
def get_acvp_v1_test_session(sessionId: str) -> Any:
    return get_test_session(sessionId)


@router.get("/testSessions/{sessionId}/vectorSets")
def get_acvp_v1_test_session_vector_sets(sessionId: str) -> Any:
    return get_test_session_vector_sets(sessionId)


@router.post("/testSessions/{sessionId}/vectorSets/generate")
def generate_acvp_v1_test_session_vector_sets(
    sessionId: str,
    payload: Any = Body(default=None),
) -> Any:
    request = _parse_vector_set_generate_request(payload)
    if isinstance(request, JSONResponse):
        return request
    return generate_vector_sets_for_session(sessionId, request)


@router.get("/testSessions/{sessionId}/results")
def get_acvp_v1_test_session_results(sessionId: str) -> Any:
    return get_test_session_results(sessionId)


@router.delete("/testSessions/{sessionId}")
def delete_acvp_v1_test_session(sessionId: str) -> Any:
    return delete_test_session(sessionId)


@router.get("/vectorSets/{vectorSetId}")
def get_acvp_v1_vector_set(vectorSetId: str) -> Any:
    return get_vector_set(vectorSetId)


@router.post("/vectorSets/{vectorSetId}/results")
def submit_acvp_v1_vector_set_results(
    vectorSetId: str,
    payload: Any = Body(...),
) -> Any:
    request = _parse_results_submit_request(payload)
    if isinstance(request, JSONResponse):
        return request
    return submit_vector_set_results(vectorSetId, request.response)


@router.get("/vectorSets/{vectorSetId}/results")
def get_acvp_v1_vector_set_results(vectorSetId: str) -> Any:
    return get_vector_set_results(vectorSetId)


@router.get("/vectorSets/{vectorSetId}/expectedResults")
def get_acvp_v1_vector_set_expected_results(vectorSetId: str) -> Any:
    return get_vector_set_expected_results(vectorSetId)


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
