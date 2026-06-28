from __future__ import annotations

import os
from typing import Optional


LOCAL_WORKFLOW_PROFILE = "local"
STRICT_WORKFLOW_PROFILE = "strict"
WORKFLOW_PROFILES = {LOCAL_WORKFLOW_PROFILE, STRICT_WORKFLOW_PROFILE}
ENV_WORKFLOW_PROFILE = "ACVP_WORKFLOW_PROFILE"


class WorkflowProfileError(ValueError):
    def __init__(self, value: object):
        self.value = value
        super().__init__(
            "workflowProfile must be one of: "
            + ", ".join(sorted(WORKFLOW_PROFILES))
        )


def default_workflow_profile() -> str:
    value = os.getenv(ENV_WORKFLOW_PROFILE)
    if value in WORKFLOW_PROFILES:
        return str(value)
    return LOCAL_WORKFLOW_PROFILE


def resolve_workflow_profile(value: Optional[str]) -> str:
    if value is None:
        return default_workflow_profile()
    if value not in WORKFLOW_PROFILES:
        raise WorkflowProfileError(value)
    return value


def is_strict_workflow(profile: str) -> bool:
    return profile == STRICT_WORKFLOW_PROFILE

