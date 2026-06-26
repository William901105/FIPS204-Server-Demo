from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field


JsonObject = Union[Dict[str, Any], List[Any]]


class ImportRequest(BaseModel):
    prompt: JsonObject
    expectedResults: JsonObject
    response: JsonObject
    label: Optional[str] = None


class GeneratedKeygenImportRequest(BaseModel):
    prompt: JsonObject
    response: JsonObject
    label: Optional[str] = None


class ValidateRequest(BaseModel):
    importId: str


class LoadSampleRequest(BaseModel):
    sampleName: str
    responseVariant: Literal["pass", "fail"] = "pass"


class ImportSummary(BaseModel):
    importId: str
    label: Optional[str] = None
    vsId: Any = None
    algorithm: Optional[str] = None
    mode: Optional[str] = None
    revision: Optional[str] = None
    testGroupCount: int = 0
    testCaseCount: int = 0


class ApiError(BaseModel):
    detail: str = Field(..., examples=["Unknown importId"])


class MldsaKeygenRequest(BaseModel):
    parameterSet: str
    seed: str


class MldsaKeygenResponse(BaseModel):
    algorithm: Literal["ML-DSA"] = "ML-DSA"
    mode: Literal["keyGen"] = "keyGen"
    revision: Literal["FIPS204"] = "FIPS204"
    parameterSet: str
    seed: str
    pk: str
    sk: str


class MldsaKeygenExpectedResultsRequest(BaseModel):
    prompt: JsonObject


class MldsaKeygenExpectedResultsResponse(BaseModel):
    algorithm: Literal["ML-DSA"] = "ML-DSA"
    mode: Literal["keyGen"] = "keyGen"
    revision: Literal["FIPS204"] = "FIPS204"
    expectedResults: JsonObject


class MldsaSigGenRequest(BaseModel):
    parameterSet: Literal["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    signatureInterface: Literal["internal"] = "internal"
    externalMu: Literal[False] = False
    deterministic: Literal[True] = True
    sk: str
    message: str


class MldsaSigGenResponse(BaseModel):
    algorithm: Literal["ML-DSA"] = "ML-DSA"
    mode: Literal["sigGen"] = "sigGen"
    revision: Literal["FIPS204"] = "FIPS204"
    parameterSet: str
    signatureInterface: Literal["internal"] = "internal"
    externalMu: Literal[False] = False
    deterministic: Literal[True] = True
    signature: str
