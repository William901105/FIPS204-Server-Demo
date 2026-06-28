from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body
from fastapi import Response
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
from .paging import parse_paging_params
from .workflow_profile import (
    LOCAL_WORKFLOW_PROFILE,
    STRICT_WORKFLOW_PROFILE,
    WorkflowProfileError,
    is_strict_workflow,
    resolve_workflow_profile,
)


router = APIRouter(prefix="/acvp/v1", tags=["ACVP v1 skeleton"])


@router.get("/version")
def get_acvp_v1_version(
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        version(),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/algorithms")
def get_acvp_v1_algorithms(
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        algorithms(),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions")
def list_acvp_v1_test_sessions(
    status: Optional[str] = None,
    limit: Any = None,
    offset: Any = None,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    paging = parse_paging_params(limit=limit, offset=offset)
    if isinstance(paging, JSONResponse):
        return _canonical_response(
            paging,
            workflow_profile=workflow_profile,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        list_test_sessions(
            status=status,
            limit=paging["limit"],
            offset=paging["offset"],
        ),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions")
def create_acvp_v1_test_session(
    payload: Any = Body(...),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    request = _parse_session_create_request(payload)
    if isinstance(request, JSONResponse):
        return _canonical_response(
            request,
            workflow_profile=workflow_profile,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        create_test_session(request, workflow_profile=workflow_profile),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}")
def get_acvp_v1_test_session(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        get_test_session(sessionId),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets")
def get_acvp_v1_test_session_vector_sets(
    sessionId: str,
    status: Optional[str] = None,
    limit: Any = None,
    offset: Any = None,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    paging = parse_paging_params(limit=limit, offset=offset)
    if isinstance(paging, JSONResponse):
        return _canonical_response(
            paging,
            workflow_profile=workflow_profile,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        get_test_session_vector_sets(
            sessionId,
            status=status,
            limit=paging["limit"],
            offset=paging["offset"],
        ),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions/{sessionId}/vectorSets/generate")
def generate_acvp_v1_test_session_vector_sets(
    sessionId: str,
    payload: Any = Body(default=None),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _local_helper_route_disabled(
                "/acvp/v1/testSessions/{sessionId}/vectorSets/generate"
            ),
            workflow_profile=workflow_profile,
        )
    request = _parse_vector_set_generate_request(payload)
    if isinstance(request, JSONResponse):
        return _canonical_response(
            request,
            workflow_profile=workflow_profile,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        generate_vector_sets_for_session(sessionId, request),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets/{vectorSetId}")
def get_acvp_v1_test_session_vector_set(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        get_vector_set_prompt(sessionId, vectorSetId, workflow_profile=workflow_profile),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.delete("/testSessions/{sessionId}/vectorSets/{vectorSetId}")
def delete_acvp_v1_test_session_vector_set(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        cancel_vector_set(sessionId, vectorSetId),
        workflow_profile=workflow_profile,
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
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    submission = parse_acvp_results_submission_payload(payload)
    if isinstance(submission, JSONResponse):
        return _canonical_response(
            submission,
            workflow_profile=workflow_profile,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        submit_vector_set_results(
            sessionId,
            vectorSetId,
            submission["response"],
            show_expected=submission["showExpected"],
            workflow_profile=workflow_profile,
        ),
        workflow_profile=workflow_profile,
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
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    submission = parse_acvp_results_submission_payload(payload)
    if isinstance(submission, JSONResponse):
        return _canonical_response(
            submission,
            workflow_profile=workflow_profile,
            profile=profile,
            include_local_metadata=includeLocalMetadata,
        )
    return _canonical_response(
        submit_vector_set_results(
            sessionId,
            vectorSetId,
            submission["response"],
            show_expected=submission["showExpected"],
            update=True,
            workflow_profile=workflow_profile,
        ),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets/{vectorSetId}/results")
def get_acvp_v1_test_session_vector_set_results(
    sessionId: str,
    vectorSetId: str,
    showExpected: bool = False,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        get_vector_set_results(
            sessionId,
            vectorSetId,
            workflow_profile=workflow_profile,
            show_expected=showExpected,
        ),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/vectorSets/{vectorSetId}/expected")
def get_acvp_v1_test_session_vector_set_expected(
    sessionId: str,
    vectorSetId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        get_vector_set_expected(sessionId, vectorSetId, workflow_profile=workflow_profile),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/testSessions/{sessionId}/results")
def get_acvp_v1_test_session_results(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        get_test_session_results(sessionId, workflow_profile=workflow_profile),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.post("/testSessions/{sessionId}/submit")
def submit_acvp_v1_test_session(
    sessionId: str,
    payload: Any = Body(default=None),
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _local_helper_route_disabled("/acvp/v1/testSessions/{sessionId}/submit"),
            workflow_profile=workflow_profile,
        )
    return _canonical_response(
        submit_test_session_for_validation(sessionId),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.delete("/testSessions/{sessionId}")
def delete_acvp_v1_test_session(
    sessionId: str,
    profile: Optional[str] = None,
    includeLocalMetadata: bool = False,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _canonical_response(workflow_profile, workflow_profile=LOCAL_WORKFLOW_PROFILE)
    return _canonical_response(
        delete_test_session(sessionId),
        workflow_profile=workflow_profile,
        profile=profile,
        include_local_metadata=includeLocalMetadata,
    )


@router.get("/vectorSets/{vectorSetId}")
def get_acvp_v1_vector_set(
    vectorSetId: str,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _compatibility_alias_response(workflow_profile)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _flat_alias_disabled(),
            workflow_profile=workflow_profile,
        )
    return _compatibility_alias_response(get_vector_set(vectorSetId))


@router.delete("/vectorSets/{vectorSetId}")
def delete_acvp_v1_vector_set(
    vectorSetId: str,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _compatibility_alias_response(workflow_profile)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _flat_alias_disabled(),
            workflow_profile=workflow_profile,
        )
    return _compatibility_alias_response(cancel_vector_set(None, vectorSetId))


@router.post("/vectorSets/{vectorSetId}/results")
def submit_acvp_v1_vector_set_results(
    vectorSetId: str,
    payload: Any = Body(...),
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _compatibility_alias_response(workflow_profile)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _flat_alias_disabled(),
            workflow_profile=workflow_profile,
        )
    submission = parse_acvp_results_submission_payload(payload)
    if isinstance(submission, JSONResponse):
        return _compatibility_alias_response(submission)
    return _compatibility_alias_response(
        submit_vector_set_results(
            None,
            vectorSetId,
            submission["response"],
            show_expected=submission["showExpected"],
        )
    )


@router.get("/vectorSets/{vectorSetId}/results")
def get_acvp_v1_vector_set_results(
    vectorSetId: str,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _compatibility_alias_response(workflow_profile)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _flat_alias_disabled(),
            workflow_profile=workflow_profile,
        )
    return _compatibility_alias_response(get_vector_set_results(None, vectorSetId))


@router.get("/vectorSets/{vectorSetId}/expectedResults")
def get_acvp_v1_vector_set_expected_results(
    vectorSetId: str,
    workflowProfile: Optional[str] = None,
) -> Any:
    workflow_profile = _resolve_workflow_profile_or_error(workflowProfile)
    if isinstance(workflow_profile, JSONResponse):
        return _compatibility_alias_response(workflow_profile)
    if is_strict_workflow(workflow_profile):
        return _canonical_response(
            _flat_alias_disabled(),
            workflow_profile=workflow_profile,
        )
    return _compatibility_alias_response(get_vector_set_expected_results(vectorSetId))


def _resolve_workflow_profile_or_error(value: Optional[str]) -> Any:
    try:
        return resolve_workflow_profile(value)
    except WorkflowProfileError as exc:
        return acvp_skeleton_error(
            400,
            "INVALID_WORKFLOW_PROFILE",
            str(exc),
            "$.workflowProfile",
            details={"workflowProfile": value},
        )


def _flat_alias_disabled() -> JSONResponse:
    return acvp_skeleton_error(
        404,
        "LOCAL_COMPATIBILITY_ALIAS_DISABLED",
        "This flat vectorSet alias is only available in local workflow profile.",
        "$.workflowProfile",
    )


def _local_helper_route_disabled(route: str) -> JSONResponse:
    return acvp_skeleton_error(
        409,
        "LOCAL_HELPER_ROUTE_DISABLED",
        "This local helper route is only available in local workflow profile.",
        route,
    )


def _canonical_response(
    value: Any,
    *,
    workflow_profile: str = LOCAL_WORKFLOW_PROFILE,
    profile: Optional[str] = None,
    include_local_metadata: bool = False,
) -> Any:
    if isinstance(value, Response) and not isinstance(value, JSONResponse):
        return value
    if is_strict_workflow(workflow_profile):
        if isinstance(value, JSONResponse):
            content = _json_response_content(value)
            if _is_acvp_envelope(content):
                body = _strict_protocol_body(content[1])
                strict_content = [content[0], body]
                return JSONResponse(
                    status_code=value.status_code,
                    content=strict_content,
                    headers=_forwarded_headers(value),
                )
            body = _strict_protocol_body(_json_response_body_from_content(content))
            return JSONResponse(
                status_code=value.status_code,
                content=envelope_response(body, include_local_metadata=False),
                headers=_forwarded_headers(value),
            )
        return envelope_response(_strict_protocol_body(value), include_local_metadata=False)
    if profile == "debug" or include_local_metadata:
        return value
    if isinstance(value, JSONResponse):
        content = _json_response_content(value)
        if _is_acvp_envelope(content):
            return JSONResponse(
                status_code=value.status_code,
                content=content,
                headers=_forwarded_headers(value),
            )
        body = _json_response_body_from_content(content)
        return JSONResponse(
            status_code=value.status_code,
            content=envelope_response(body, include_local_metadata=True),
            headers=_forwarded_headers(value),
        )
    return envelope_response(value, include_local_metadata=True)


def _strict_protocol_body(value: Any) -> Any:
    if isinstance(value, list):
        return [_strict_protocol_body(item) for item in value]
    if not isinstance(value, dict):
        return value

    body = {
        key: _strict_protocol_body(item)
        for key, item in value.items()
        if key
        not in {
            "productionReady",
            "profile",
            "demoOnly",
            "notProductionAcvp",
            "localSkeletonBehavior",
            "localCompatibilityAlias",
            "localPostReturnsResults",
            "localPutReplaceBehavior",
            "localSkeletonPutReplaceBehavior",
        }
    }

    extensions = body.get("extensions")
    if isinstance(extensions, dict):
        extensions = dict(extensions)
        extensions.pop("localFips204Skeleton", None)
        if extensions:
            body["extensions"] = extensions
        else:
            body.pop("extensions", None)

    links = body.get("links")
    if isinstance(links, dict) and "previous" in links:
        links = dict(links)
        links["prev"] = links.pop("previous")
        body["links"] = links
    return body


def _compatibility_alias_response(value: Any) -> Any:
    if isinstance(value, JSONResponse):
        body = _with_compatibility_alias(_json_response_body(value))
        return JSONResponse(
            status_code=value.status_code,
            content=body,
            headers=_forwarded_headers(value),
        )
    return _with_compatibility_alias(value)


def _with_compatibility_alias(body: Any) -> Any:
    if not isinstance(body, dict):
        return body
    aliased = dict(body)
    local_extension = aliased.get("extensions", {}).get("localFips204Skeleton")
    if isinstance(local_extension, dict):
        for key in (
            "vectorSetId",
            "testSessionId",
            "status",
            "submissionAction",
            "localSkeletonPutReplaceBehavior",
            "localPostReturnsResults",
            "validationResult",
            "report",
            "stateHistory",
        ):
            if key in local_extension and key not in aliased:
                aliased[key] = local_extension[key]
    if "results" in aliased:
        aliased["acvpResults"] = {"results": aliased["results"]}
    aliased["localCompatibilityAlias"] = True
    return aliased


def _json_response_body(response: JSONResponse) -> Dict[str, Any]:
    content = _json_response_content(response)
    return _json_response_body_from_content(content)


def _json_response_content(response: JSONResponse) -> Any:
    return json.loads(response.body.decode("utf-8"))


def _json_response_body_from_content(content: Any) -> Dict[str, Any]:
    if not isinstance(content, dict):
        return {"value": content}
    return content


def _is_acvp_envelope(content: Any) -> bool:
    return (
        isinstance(content, list)
        and len(content) >= 2
        and isinstance(content[0], dict)
        and content[0].get("acvVersion") == "1.0"
    )


def _forwarded_headers(response: JSONResponse) -> Dict[str, str]:
    request_id = response.headers.get("X-Request-ID")
    return {"X-Request-ID": request_id} if request_id else {}


def parse_acvp_results_submission_payload(payload: Any) -> Any:
    if isinstance(payload, AcvpV1VectorSetResultsSubmitRequest):
        return {
            "response": payload.response,
            "showExpected": False,
        }
    if isinstance(payload, list):
        return _parse_acvp_results_envelope(payload)
    if isinstance(payload, dict):
        if "response" in payload:
            response = payload.get("response")
            show_expected = _bool_value(payload.get("showExpected"))
            if isinstance(response, dict) and "showExpected" in response:
                response, nested_show_expected = _without_show_expected(response)
                show_expected = nested_show_expected
            return {
                "response": response,
                "showExpected": show_expected,
            }
        if _looks_like_vector_set_response(payload):
            response, show_expected = _without_show_expected(payload)
            return {
                "response": response,
                "showExpected": show_expected,
            }
        return acvp_skeleton_error(
            400,
            "INVALID_REQUEST",
            "Request must be a local response wrapper, ACVP envelope, or response body.",
            "$",
        )
    return acvp_skeleton_error(
        400,
        "INVALID_REQUEST",
        "Request body must be a JSON object or ACVP array envelope.",
        "$",
    )


def _parse_acvp_results_envelope(payload: Any) -> Any:
    if len(payload) < 2:
        return acvp_skeleton_error(
            400,
            "INVALID_ACVP_ENVELOPE",
            "ACVP envelope must contain version and body objects.",
            "$",
        )
    version = payload[0]
    if not isinstance(version, dict) or "acvVersion" not in version:
        return acvp_skeleton_error(
            400,
            "INVALID_ACVP_ENVELOPE",
            "ACVP envelope must start with an acvVersion object.",
            "$[0].acvVersion",
        )
    if version.get("acvVersion") != "1.0":
        return acvp_skeleton_error(
            400,
            "UNSUPPORTED_ACVP_VERSION",
            "Only acvVersion 1.0 is supported by this local skeleton.",
            "$[0].acvVersion",
        )
    body = payload[1]
    if not isinstance(body, dict):
        return acvp_skeleton_error(
            400,
            "INVALID_ACVP_ENVELOPE",
            "ACVP results envelope body must be a JSON object.",
            "$[1]",
        )
    response, show_expected = _without_show_expected(body)
    return {
        "response": response,
        "showExpected": show_expected,
    }


def _without_show_expected(body: Dict[str, Any]) -> tuple[Dict[str, Any], bool]:
    response = dict(body)
    show_expected = _bool_value(response.pop("showExpected", False))
    return response, show_expected


def _bool_value(value: Any) -> bool:
    return value is True


def _looks_like_vector_set_response(payload: Dict[str, Any]) -> bool:
    return bool({"vsId", "algorithm", "mode", "revision", "testGroups"}.intersection(payload))


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
