"""Golden-schema test — protects the fuzz contract.

generate_fuzz_script.py slices function source using results[].line_start /
line_end. This test pins that schema on the shared report writer. It skips when
numpy is unavailable (the writer lives in the numpy-importing vuln_scanner
module), so it is a no-op in a minimal env and a real guard in the full one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("numpy")  # save_json_report lives in a numpy-importing module

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))


def test_save_json_report_preserves_line_contract(tmp_path):
    from agentsec.reporting import save_json_report

    results = [
        {
            "function": {"name": "get_user", "lineno": 33, "end_lineno": 42},
            "findings": [
                {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "severity": "HIGH",
                 "confidence": 0.9, "line_hint": "", "description": "", "evidence": "",
                 "solution": "", "references": []},
            ],
        },
        {"function": {"name": "init_db", "lineno": 8, "end_lineno": 30}, "findings": []},
    ]
    out = tmp_path / "vuln_report.json"
    save_json_report(Path("targets/test_target2.py"), results, out, elapsed=1.0, model="qwen3")

    report = json.loads(out.read_text())
    entry = next(r for r in report["results"] if r["function"] == "get_user")
    assert entry["line_start"] == 33      # the contract generate_fuzz_script depends on
    assert entry["line_end"] == 42
    assert entry["findings"][0]["cwe_id"] == "CWE-89"
