"""Coverage computation for build_corpus.py — the dedup + JSON gate must match
what s2_curate keeps, so the report reflects the real trainable dataset."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_corpus import compute_coverage  # noqa: E402


def _log(tmp_path, records) -> Path:
    p = tmp_path / "analyze_code.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records))
    return p


def _rec(system, user, output, success=True):
    return {"system_prompt": system, "user_prompt": user,
            "output": output, "success": success}


def test_dedup_benign_and_cwe_counting(tmp_path):
    findings = json.dumps([{"cwe_id": "CWE-89"}, {"cwe_id": "CWE-79"}])
    log = _log(tmp_path, [
        _rec("sys", "fnA", findings),          # 2 findings
        _rec("sys", "fnA", findings),          # exact dup → collapses
        _rec("sys", "fnB", "[]"),              # benign
        _rec("sys", "fnC", "```json\n[{\"cwe_id\": \"CWE-89\"}]\n```"),  # fenced, still counts
        _rec("sys", "fnD", "not json", success=True),   # non-JSON → dropped
        _rec("sys", "fnE", findings, success=False),    # failed call → dropped
    ])
    cov = compute_coverage(log)
    assert cov["unique"] == 3          # fnA (deduped), fnB, fnC
    assert cov["benign"] == 1          # fnB
    assert cov["cwes"]["CWE-89"] == 2  # fnA + fnC
    assert cov["cwes"]["CWE-79"] == 1  # fnA


def test_cwe_id_normalized(tmp_path):
    log = _log(tmp_path, [
        _rec("s", "u1", json.dumps([{"cwe_id": "cwe_89"}])),
        _rec("s", "u2", json.dumps([{"cwe_id": "CWE-89: SQL Injection"}])),
    ])
    cov = compute_coverage(log)
    assert cov["cwes"]["CWE-89"] == 2  # both messy forms normalize to CWE-89


def test_missing_log_is_empty(tmp_path):
    cov = compute_coverage(tmp_path / "nope.jsonl")
    assert cov == {"unique": 0, "benign": 0, "cwes": cov["cwes"]}
    assert len(cov["cwes"]) == 0
