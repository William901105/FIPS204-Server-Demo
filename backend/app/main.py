from __future__ import annotations

from typing import Any, Dict
from uuid import uuid4

from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .acvp_mldsa.errors import AcvpSchemaError
from .acvp_mldsa.validators import (
    validate_mldsa_registration,
    validate_mldsa_response,
    validate_mldsa_vector_set,
)
from .acvp_parser import AcvpParseError, normalize_acvp_json, summarize_vector_set
from .crypto_oracle.mldsa_oracle import (
    MldsaOracleError,
    MldsaOracleInputError,
    keygen_internal,
)
from .models import (
    ImportRequest,
    ImportSummary,
    LoadSampleRequest,
    MldsaKeygenRequest,
    MldsaKeygenResponse,
    ValidateRequest,
)
from .report import build_report
from .sample_loader import SampleLoaderError, list_sample_data, load_sample
from .validator import validate


app = FastAPI(
    title="FIPS 204 / ML-DSA ACVP JSON Viewer + Local Validator",
    version="0.1.0",
    description="Local JSON comparison demo for ML-DSA ACVP prompt, expectedResults, and response files.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

IMPORT_STORE: Dict[str, Dict[str, Any]] = {}


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/schema/mldsa/registration")
def validate_mldsa_registration_schema(payload: Any = Body(...)) -> Any:
    try:
        normalized = validate_mldsa_registration(payload)
    except AcvpSchemaError as exc:
        return _schema_error_response(exc)
    return {"ok": True, "type": "registration", "normalized": normalized}


@app.post("/api/schema/mldsa/vector-set")
def validate_mldsa_vector_set_schema(payload: Any = Body(...)) -> Any:
    try:
        normalized = validate_mldsa_vector_set(payload)
    except AcvpSchemaError as exc:
        return _schema_error_response(exc)
    return {"ok": True, "type": "vector-set", "normalized": normalized}


@app.post("/api/schema/mldsa/response")
def validate_mldsa_response_schema(payload: Any = Body(...)) -> Any:
    try:
        normalized = validate_mldsa_response(payload)
    except AcvpSchemaError as exc:
        return _schema_error_response(exc)
    return {"ok": True, "type": "response", "normalized": normalized}


@app.post("/api/oracle/mldsa/keygen", response_model=MldsaKeygenResponse)
def mldsa_keygen(payload: MldsaKeygenRequest) -> MldsaKeygenResponse:
    try:
        result = keygen_internal(payload.parameterSet, payload.seed)
    except MldsaOracleInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except MldsaOracleError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return MldsaKeygenResponse(
        parameterSet=payload.parameterSet,
        seed=payload.seed.upper(),
        pk=result["pk"],
        sk=result["sk"],
    )


@app.post("/api/import", response_model=ImportSummary)
def import_bundle(payload: ImportRequest) -> Any:
    try:
        prompt_vs = validate_mldsa_vector_set(payload.prompt)
        mode = prompt_vs.get("mode")
        validate_mldsa_response(payload.expectedResults, expected_mode=mode)
        validate_mldsa_response(payload.response, expected_mode=mode)
        bundle = {
            "prompt": payload.prompt,
            "expectedResults": payload.expectedResults,
            "response": payload.response,
            "label": payload.label,
        }
        return _store_import(bundle)
    except AcvpSchemaError as exc:
        return _schema_error_response(exc)
    except (AcvpParseError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/validate")
def validate_import(payload: ValidateRequest) -> Dict[str, Any]:
    bundle = _get_bundle(payload.importId)
    try:
        result = validate(bundle)
    except (AcvpParseError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    bundle["validationResult"] = result
    bundle["report"] = build_report(payload.importId, result)
    return result


@app.get("/api/import/{import_id}")
def get_import(import_id: str) -> Dict[str, Any]:
    bundle = _get_bundle(import_id)
    prompt_vs = normalize_acvp_json(bundle["prompt"])
    expected_vs = normalize_acvp_json(bundle["expectedResults"])
    response_vs = normalize_acvp_json(bundle["response"])
    return {
        "importId": import_id,
        "label": bundle.get("label"),
        "summary": _summarize_bundle(import_id, bundle),
        "prompt": prompt_vs,
        "expectedResults": expected_vs,
        "response": response_vs,
        "validationResult": bundle.get("validationResult"),
    }


@app.get("/api/report/{import_id}")
def get_report(import_id: str) -> Dict[str, Any]:
    bundle = _get_bundle(import_id)
    if "report" not in bundle:
        result = validate(bundle)
        bundle["validationResult"] = result
        bundle["report"] = build_report(import_id, result)
    return bundle["report"]


@app.get("/api/sample-data")
def sample_data() -> Dict[str, Any]:
    return {"samples": list_sample_data()}


@app.post("/api/load-sample", response_model=ImportSummary)
def load_sample_import(payload: LoadSampleRequest) -> ImportSummary:
    try:
        bundle = load_sample(payload.sampleName, payload.responseVariant)
        return _store_import(bundle)
    except (SampleLoaderError, AcvpParseError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _store_import(bundle: Dict[str, Any]) -> ImportSummary:
    prompt_vs = normalize_acvp_json(bundle["prompt"])
    normalize_acvp_json(bundle["expectedResults"])
    normalize_acvp_json(bundle["response"])

    import_id = str(uuid4())
    IMPORT_STORE[import_id] = bundle
    return _summarize_bundle(import_id, bundle)


def _summarize_bundle(import_id: str, bundle: Dict[str, Any]) -> ImportSummary:
    prompt_summary = summarize_vector_set(normalize_acvp_json(bundle["prompt"]))
    return ImportSummary(importId=import_id, label=bundle.get("label"), **prompt_summary)


def _get_bundle(import_id: str) -> Dict[str, Any]:
    bundle = IMPORT_STORE.get(import_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Unknown importId")
    return bundle


def _schema_error_response(exc: AcvpSchemaError) -> JSONResponse:
    return JSONResponse(status_code=400, content=exc.to_dict())
