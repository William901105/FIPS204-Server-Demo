# ACVP v1 Skeleton

Phase 3-2 added a formal `/acvp/v1` namespace as a local skeleton. Phase 3-3 extended it with local ML-DSA registration/capabilities negotiation. Phase 3-4 adds deterministic local vector generation from negotiated capabilities. It is not a production-ready ACVP server and every response includes:

```json
{
  "productionReady": false,
  "profile": "local-fips204-skeleton",
  "demoOnly": true,
  "notProductionAcvp": true
}
```

References:

- ACVP Protocol Specification: https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html
- ACVP ML-DSA JSON Specification: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html
- ACVP documentation landing page: https://pages.nist.gov/ACVP/
- FIPS 204: https://csrc.nist.gov/pubs/fips/204/final

## Endpoints

| Method | Path | Current skeleton behavior |
| --- | --- | --- |
| GET | `/acvp/v1/version` | Returns local skeleton protocol/version metadata. |
| GET | `/acvp/v1/algorithms` | Returns ML-DSA capability summary for the local implementation. |
| GET | `/acvp/v1/testSessions` | Lists in-memory skeleton sessions. |
| POST | `/acvp/v1/testSessions` | Creates a local prompt-based skeleton session or a registration session that can generate vector sets. |
| GET | `/acvp/v1/testSessions/{sessionId}` | Returns skeleton session detail and vector set metadata. |
| GET | `/acvp/v1/testSessions/{sessionId}/vectorSets` | Lists vector sets for a skeleton session; registration-only sessions return an empty list and Phase 3-4 next action. |
| POST | `/acvp/v1/testSessions/{sessionId}/vectorSets/generate` | Generates vector sets for a capabilitiesAccepted session. |
| GET | `/acvp/v1/vectorSets/{vectorSetId}` | Returns the local prompt/vector set. This is a skeleton convenience path, not a production claim. |
| POST | `/acvp/v1/vectorSets/{vectorSetId}/results` | Validates a submitted response against generated expectedResults. |
| GET | `/acvp/v1/vectorSets/{vectorSetId}/results` | Returns stored local validation result. |
| GET | `/acvp/v1/vectorSets/{vectorSetId}/expectedResults` | Returns generated expectedResults as local skeleton behavior. Production ACVP handling requires spec review. |
| GET | `/acvp/v1/testSessions/{sessionId}/results` | Aggregates local vector set results; registration-only sessions return `409 VECTOR_SETS_NOT_GENERATED`. |
| DELETE | `/acvp/v1/testSessions/{sessionId}` | Deletes the in-memory skeleton session and vector set mappings. |

## Create Session Example

Request:

```json
{
  "prompt": {
    "vsId": 3101,
    "algorithm": "ML-DSA",
    "mode": "keyGen",
    "revision": "FIPS204",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-DSA-44",
        "tests": [
          {
            "tcId": 1,
            "seed": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
          }
        ]
      }
    ]
  },
  "label": "phase 3-2 keyGen skeleton",
  "autoGenerateExpectedResults": true
}
```

Response shape:

```json
{
  "testSessionId": "uuid",
  "status": "vectorReady",
  "vectorSetUrls": ["/acvp/v1/vectorSets/uuid"],
  "vectorSetIds": ["uuid"],
  "productionReady": false,
  "profile": "local-fips204-skeleton",
  "demoOnly": true,
  "notProductionAcvp": true
}
```

## Registration Session Example

Phase 3-4 accepts a local skeleton registration container and generates vector sets by default:

```json
{
  "algorithms": [
    {
      "algorithm": "ML-DSA",
      "mode": "keyGen",
      "revision": "FIPS204",
      "parameterSets": ["ML-DSA-44", "ML-DSA-65"]
    }
  ],
  "label": "phase 3-4 keyGen vectors",
  "campaignSeed": "00112233445566778899AABBCCDDEEFF",
  "testsPerGroup": 2,
  "autoGenerateVectorSets": true
}
```

Response shape:

```json
{
  "testSessionId": "uuid",
  "status": "vectorReady",
  "vectorSetIds": ["uuid"],
  "vectorSetUrls": ["/acvp/v1/vectorSets/uuid"],
  "negotiatedCapabilities": {
    "algorithm": "ML-DSA",
    "revision": "FIPS204",
    "negotiated": [],
    "unsupported": [],
    "warnings": []
  },
  "vectorGeneration": {
    "campaignSeed": "00112233445566778899AABBCCDDEEFF",
    "testsPerGroup": 2,
    "generatedVectorSetCount": 1,
    "modes": ["keyGen"],
    "generationProfile": "phase-3-4-deterministic-local",
    "localSkeletonBehavior": true
  },
  "productionReady": false,
  "profile": "local-fips204-skeleton",
  "demoOnly": true,
  "notProductionAcvp": true
}
```

## Submit Results Example

The local skeleton can return generated expectedResults:

```json
{
  "vectorSetId": "uuid",
  "expectedResults": {
    "vsId": 3101,
    "algorithm": "ML-DSA",
    "mode": "keyGen",
    "revision": "FIPS204",
    "testGroups": []
  },
  "productionReady": false,
  "profile": "local-fips204-skeleton",
  "demoOnly": true,
  "notProductionAcvp": true
}
```

A local response submission wraps an ML-DSA response object:

```json
{
  "response": {
    "vsId": 3101,
    "algorithm": "ML-DSA",
    "mode": "keyGen",
    "revision": "FIPS204",
    "testGroups": []
  }
}
```

The response includes `validationResult` and `report` fields from the local validator. This is local skeleton behavior and does not replace a formal production ACVP validation workflow.

## Exclusions

The skeleton intentionally does not include:

- login/JWT
- mTLS
- DB persistence
- official production ACVP certification workflow
- vendor/module/OE/dependency CRUD
- async or large submission handling

Planned follow-up phases:

- Phase 3-5 formal state machine
- Phase 4-1 DB persistence
- Phase 4-2 auth/JWT/mTLS
- Phase 4-3 paging/error/query
- Phase 4-4 async/large submission
- Phase 5-x interoperability/security/deployment
