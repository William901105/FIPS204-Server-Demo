from __future__ import annotations


class MldsaOracleError(Exception):
    """Base error raised by the ML-DSA native oracle wrapper."""


class MldsaOracleInputError(MldsaOracleError):
    """Raised when the caller provides invalid oracle input."""


class MldsaOracleConfigError(MldsaOracleError):
    """Raised when the native oracle binary is missing or misconfigured."""


class MldsaOracleExecutionError(MldsaOracleError):
    """Raised when the native oracle fails or returns invalid output."""
