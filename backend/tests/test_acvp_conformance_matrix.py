from __future__ import annotations

from pathlib import Path


DOC = Path(__file__).resolve().parents[1] / "docs" / "acvp-conformance-matrix.md"
VECTOR_GENERATION_DOC = (
    Path(__file__).resolve().parents[1] / "docs" / "acvp-v1-vector-generation.md"
)
PROTOCOL_HARDENING_DOC = (
    Path(__file__).resolve().parents[1] / "docs" / "acvp-v1-protocol-hardening.md"
)


def test_acvp_conformance_matrix_exists_and_references_nist_sources() -> None:
    assert DOC.exists()
    text = DOC.read_text(encoding="utf-8")

    assert "https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html" in text
    assert "https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html" in text
    assert "https://pages.nist.gov/ACVP/" in text
    assert "https://csrc.nist.gov/pubs/fips/204/final" in text


def test_acvp_conformance_matrix_has_required_status_values() -> None:
    text = DOC.read_text(encoding="utf-8")

    for status in (
        "SUPPORTED",
        "SUPPORTED-LOCAL",
        "PARTIAL",
        "MISSING",
        "LOCAL_DEMO_ONLY",
        "NOT_IN_SCOPE_YET",
        "NEEDS_SPEC_REVIEW",
    ):
        assert status in text


def test_acvp_conformance_matrix_declares_demo_and_skeleton_not_production() -> None:
    text = DOC.read_text(encoding="utf-8")

    assert "`/api/demo/acvp/...` routes are a local demo lifecycle" in text
    assert "not formal ACVP endpoints" in text
    assert "`/acvp/v1/...` routes are skeleton endpoints" in text
    assert "Phase 3-4 vector generation, Phase 3-5 lifecycle state, and Phase 4-1 SQLite persistence" in text
    assert "deterministic/local-fips204-skeleton behavior" in text
    assert "not a production-ready server" in text


def test_acvp_conformance_matrix_lists_required_future_phases() -> None:
    text = DOC.read_text(encoding="utf-8")

    for phase in (
        "Phase 3-2",
        "Phase 3-3",
        "Phase 3-4",
        "Phase 3-5",
        "Phase 4-1",
        "Phase 4-2",
        "Phase 4-3",
    ):
        assert phase in text


def test_acvp_v1_vector_generation_doc_exists_and_documents_scope() -> None:
    assert VECTOR_GENERATION_DOC.exists()
    text = VECTOR_GENERATION_DOC.read_text(encoding="utf-8")

    assert "Phase 3-4" in text
    assert "campaignSeed" in text
    assert "testsPerGroup" in text
    assert "POST /acvp/v1/testSessions/{sessionId}/vectorSets/generate" in text
    assert "not a production-ready ACVP server" in text
    assert "SHAKE-128" in text


def test_acvp_v1_protocol_hardening_doc_exists_and_documents_phase_4_3() -> None:
    assert PROTOCOL_HARDENING_DOC.exists()
    text = PROTOCOL_HARDENING_DOC.read_text(encoding="utf-8")

    assert "Phase 4-3 Commit 1" in text
    assert "/acvp/v1/testSessions/{sessionId}/vectorSets/{vectorSetId}/expected" in text
    assert "extensions.localFips204Skeleton" in text
    assert "localCompatibilityAlias=true" in text
    assert "Results disposition adapter remains Phase 4-3C" in text
