from __future__ import annotations

from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field


JsonObject = Union[dict[str, Any], list[Any]]


class ImportRequest(BaseModel):
    prompt: JsonObject
    expectedResults: JsonObject
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
