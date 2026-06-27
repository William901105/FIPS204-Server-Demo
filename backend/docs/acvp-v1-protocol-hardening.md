# ACVP v1 Protocol Hardening

This document records Phase 4-3 Commit 1: NIST canonical nested vector set routes and ACVP array envelope response adaptation.

## Scope

Implemented in this commit:

- ACVP array envelope helper for canonical `/acvp/v1` responses.
- Local skeleton metadata under `extensions.localFips204Skeleton`.
- NIST canonical nested vector set routes:
  - `GET /acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}`
  - `DELETE /acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}`
  - `POST /acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results`
  - `PUT /acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results`
  - `GET /acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results`
  - `GET /acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/expected`
- Service helpers for session lookup, vector set lookup, session/vector ownership checks, submit/update, cancel, prompt download, expected retrieval, and result retrieval.
- Flat vector set compatibility aliases retained with `localCompatibilityAlias=true`.

Not implemented in this commit:

- Results disposition adapter.
- Paging/query hardening.
- Error normalization.
- JWT, mTLS, auth, PostgreSQL, async validation, large submission, vendor/module/OE/dependency resources.

## NIST Sources

Protocol authority:

- ACVP Protocol Specification: https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html

ML-DSA JSON authority:

- ACVP ML-DSA JSON Specification: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html

Documentation index:

- ACVP documentation landing page: https://pages.nist.gov/ACVP/

The usnistgov/ACVP-Server repository is useful implementation/gen-val reference material, but it is not treated as the final authority when it differs from the protocol specification.

## Prompt Versus NIST Check

The task prompt expected nested vector set routes under `testSessions/{sessionId}` and specifically warned that expected result retrieval may be `/expected` instead of `/expectedResults`. The NIST protocol resource hierarchy uses the nested test session/vector set shape and the expected result route name `/expected`; this implementation follows the NIST route names for canonical routes.

The older local routes under `/acvp/v1/vectorSets/{vectorSetId}` are retained only as local compatibility aliases. They do not override the canonical nested routes.

## Envelope Policy

Canonical `/acvp/v1` routes return:

```json
[
  {"acvVersion": "1.0"},
  {
    "status": "vectorReady",
    "extensions": {
      "localFips204Skeleton": {
        "productionReady": false,
        "profile": "local-fips204-skeleton",
        "demoOnly": true,
        "notProductionAcvp": true
      }
    }
  }
]
```

The helper functions are:

- `acvp_envelope(body)`
- `acvp_local_metadata()`
- `with_local_metadata(body)`
- `envelope_response(body, include_local_metadata=False)`

The metadata location is intentionally under `extensions.localFips204Skeleton`; canonical protocol body fields no longer carry `productionReady`, `profile`, `demoOnly`, or `notProductionAcvp` at top level. `productionReady` remains `false`.

`/api/...` endpoints are unchanged and are not wrapped with ACVP envelopes.

## Ownership And State

Nested vector set routes enforce that the supplied `vectorSetId` belongs to the supplied `sessionId`.

- Missing session returns `404 UNKNOWN_TEST_SESSION`.
- Missing vector set returns `404 UNKNOWN_VECTOR_SET`.
- Existing vector set under a different session returns `404 UNKNOWN_VECTOR_SET` to avoid leaking existence across sessions.

`DELETE` is a soft cancel. It sets vector set status to `cancelled`, records a `state_events` row, persists the vector set, and cancels the parent session when all vector sets are cancelled.

`PUT .../results` is local skeleton replace behavior. It reuses the same validation and persistence path as POST and marks the response with `localSkeletonPutReplaceBehavior=true`.

## Remaining Deviations

- Results disposition adapter remains Phase 4-3C.
- Paging/query hardening remains Phase 4-3D.
- Error normalization remains Phase 4-3E.
- Auth/JWT/mTLS remains Phase 4-2.
- Large submission and async validation remain Phase 4-4.
- Vendor/module/OE/dependency resources are out of scope.
- This is still a local skeleton. It is not a production-ready ACVP server.
