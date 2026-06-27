# ACVP v1 Skeleton

Phase 3-2 added a formal `/acvp/v1` namespace as a local skeleton. Phase 3-3 through Phase 3-5 added local ML-DSA capabilities negotiation, deterministic vector generation, and a local test session/vector set state machine. Phase 4-1 stores sessions, vector sets, submissions, validation results, reports, and state events in SQLite.

Phase 4-3 Commit 1 adds the first protocol hardening pass:

- NIST canonical nested vector set routes under `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}`.
- ACVP array envelope responses for canonical `/acvp/v1` routes.
- Local skeleton metadata moved under `extensions.localFips204Skeleton`.
- Existing flat vector set routes retained as local compatibility aliases.

This remains a local skeleton, not a production-ready ACVP server. `/acvp/v1` still reports `productionReady=false`.

References:

- ACVP Protocol Specification: https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html
- ACVP ML-DSA JSON Specification: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html
- ACVP documentation landing page: https://pages.nist.gov/ACVP/
- FIPS 204: https://csrc.nist.gov/pubs/fips/204/final

## Protocol Authority

The NIST ACVP Protocol Specification is the protocol authority for URI hierarchy, message envelope, workflow, paging, and errors. The NIST ACVP ML-DSA JSON Specification is the algorithm JSON authority. The usnistgov/ACVP-Server repository is useful implementation/gen-val reference material, but it does not override the protocol specification when behavior differs.

For Phase 4-3 Commit 1, the prompt matched the NIST protocol on the important vector set route shape: vector set download, results, update, cancellation, and expected result retrieval are nested below `testSessions/{testSessionId}`. The prompt also correctly called out that the NIST expected result path uses `/expected`, not the old local `/expectedResults` alias.

## ACVP Envelope

Canonical `/acvp/v1` routes now return the ACVP array envelope by default:

```json
[
  {"acvVersion": "1.0"},
  {
    "testSessionId": "uuid",
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

`productionReady`, `profile`, `demoOnly`, and `notProductionAcvp` are no longer top-level fields in canonical protocol bodies. They are placed under `extensions.localFips204Skeleton` so the local skeleton status is visible without polluting the main protocol body.

For debugging, canonical routes accept `profile=debug` or `includeLocalMetadata=true` and may return the older local object shape. `/api/...` routes are not ACVP protocol routes and are not wrapped in the ACVP envelope.

## Endpoints

| Method | Path | Current skeleton behavior |
| --- | --- | --- |
| GET | `/acvp/v1/version` | Returns local skeleton protocol/version metadata in an ACVP envelope. |
| GET | `/acvp/v1/algorithms` | Returns ML-DSA capability summary for the local implementation in an ACVP envelope. |
| GET | `/acvp/v1/testSessions` | Lists SQLite-backed skeleton sessions. |
| POST | `/acvp/v1/testSessions` | Creates a local prompt-based skeleton session or a registration session that can generate vector sets. |
| GET | `/acvp/v1/testSessions/{sessionId}` | Returns skeleton session detail and vector set metadata. |
| GET | `/acvp/v1/testSessions/{sessionId}/vectorSets` | Lists vector sets for a skeleton session. |
| POST | `/acvp/v1/testSessions/{sessionId}/vectorSets/generate` | Local skeleton helper that generates vector sets for a `capabilitiesAccepted` session. |
| GET | `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}` | NIST canonical nested vector set download. Marks `ready` vector sets as `downloaded`. |
| DELETE | `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}` | NIST canonical nested vector set cancellation. Soft-cancels the vector set and records state events. |
| POST | `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results` | NIST canonical nested result submission. Stores response, validation result, and report. |
| PUT | `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results` | Local skeleton replace/update behavior for an existing result submission. |
| GET | `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/results` | Returns stored local validation result and report. Full disposition adapter remains Phase 4-3C. |
| GET | `/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/expected` | NIST canonical expected result route name. In this local skeleton it returns generated `expectedResults`; production behavior still requires NIST workflow compliance. |
| GET | `/acvp/v1/testSessions/{sessionId}/results` | Aggregates local vector set results. |
| POST | `/acvp/v1/testSessions/{sessionId}/submit` | Local skeleton session-level submit-for-validation aggregate finalization. |
| DELETE | `/acvp/v1/testSessions/{sessionId}` | Soft-cancels the SQLite-backed skeleton session and non-terminal vector sets. |

## Flat Compatibility Aliases

The older flat vector set routes remain available for local compatibility:

| Method | Path | Alias behavior |
| --- | --- | --- |
| GET | `/acvp/v1/vectorSets/{vectorSetId}` | Calls the same service logic as nested download and returns object shape with `localCompatibilityAlias=true`. |
| DELETE | `/acvp/v1/vectorSets/{vectorSetId}` | Calls the same cancellation logic without session ownership checking and returns `localCompatibilityAlias=true`. |
| POST | `/acvp/v1/vectorSets/{vectorSetId}/results` | Calls the same result submission logic and returns `localCompatibilityAlias=true`. |
| GET | `/acvp/v1/vectorSets/{vectorSetId}/results` | Calls the same result retrieval logic and returns `localCompatibilityAlias=true`. |
| GET | `/acvp/v1/vectorSets/{vectorSetId}/expectedResults` | Local compatibility alias for the old skeleton expectedResults route. |

Flat aliases are not the canonical NIST URI shape. New protocol-facing clients should use the nested `testSessions/{sessionId}/vectorSets/{vectorSetId}` routes.

## State And Persistence

Nested routes enforce session/vector set ownership. If a vector set does not belong to the supplied session, the local skeleton returns `404 UNKNOWN_VECTOR_SET` to avoid revealing vector set existence across sessions.

`DELETE` performs a soft cancel, not a hard DB row delete. It transitions the vector set to `cancelled`, records a `state_events` row, and cancels the parent session when all vector sets are cancelled. Submitting results to cancelled or expired resources returns stable `409` skeleton errors.

The default SQLite path remains `backend/data/acvp.sqlite3`; set `ACVP_DB_PATH=/path/to/acvp.sqlite3` to override it.

## Remaining Deviations

- Results disposition adapter remains Phase 4-3C.
- Paging/query hardening remains Phase 4-3D.
- Error normalization remains Phase 4-3E.
- Authentication, JWT, and mTLS remain Phase 4-2.
- Large submission and async validation remain Phase 4-4.
- Vendor/module/OE/dependency resources remain out of scope.
- This skeleton still has local helper routes such as `vectorSets/generate` and `testSessions/{sessionId}/submit`; they are documented as local behavior, not production ACVP claims.
