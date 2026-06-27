from __future__ import annotations

import copy
from typing import Any, Dict, List


LOCAL_METADATA_EXTENSION = "localFips204Skeleton"
LOCAL_METADATA_FIELDS = (
    "productionReady",
    "profile",
    "demoOnly",
    "notProductionAcvp",
)
LOCAL_METADATA: Dict[str, Any] = {
    "productionReady": False,
    "profile": "local-fips204-skeleton",
    "demoOnly": True,
    "notProductionAcvp": True,
}


def acvp_envelope(body: Dict[str, Any], *, acv_version: str = "1.0") -> List[Dict[str, Any]]:
    return [{"acvVersion": acv_version}, copy.deepcopy(body)]


def acvp_local_metadata() -> Dict[str, Any]:
    return dict(LOCAL_METADATA)


def with_local_metadata(body: Dict[str, Any]) -> Dict[str, Any]:
    protocol_body = copy.deepcopy(body)
    metadata = acvp_local_metadata()
    for field in LOCAL_METADATA_FIELDS:
        if field in protocol_body:
            metadata[field] = protocol_body.pop(field)

    extensions = protocol_body.get("extensions")
    if not isinstance(extensions, dict):
        extensions = {}
    else:
        extensions = copy.deepcopy(extensions)

    local_extension = extensions.get(LOCAL_METADATA_EXTENSION)
    if not isinstance(local_extension, dict):
        local_extension = {}
    local_extension.update(metadata)
    extensions[LOCAL_METADATA_EXTENSION] = local_extension
    protocol_body["extensions"] = extensions
    return protocol_body


def envelope_response(
    body: Dict[str, Any],
    *,
    include_local_metadata: bool = False,
) -> List[Dict[str, Any]]:
    protocol_body = with_local_metadata(body) if include_local_metadata else copy.deepcopy(body)
    return acvp_envelope(protocol_body)
