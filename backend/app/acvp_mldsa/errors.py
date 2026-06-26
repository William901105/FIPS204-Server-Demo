from __future__ import annotations

from typing import Dict, Optional


ERROR_CODES = {
    "invalid_container",
    "missing_required_field",
    "invalid_type",
    "invalid_value",
    "invalid_hex",
    "invalid_mode",
    "invalid_parameter_set",
    "invalid_conditional_field",
    "duplicate_tgId",
    "duplicate_tcId",
    "unsupported_algorithm",
    "unsupported_revision",
}


class AcvpSchemaError(Exception):
    def __init__(self, code: str, message: str, path: Optional[str] = None):
        self.code = code
        self.message = message
        self.path = path
        super().__init__(message)

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": False,
            "errorType": "schema",
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


def schema_error(code: str, message: str, path: Optional[str] = None) -> AcvpSchemaError:
    return AcvpSchemaError(code, message, path)

