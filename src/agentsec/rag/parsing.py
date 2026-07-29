"""parsing.py — finding JSON parsing + severity, reused from vuln_scanner."""

from __future__ import annotations

from vuln_scanner import (  # noqa: F401
    SEVERITY_RANK,
    extract_json_array,
    validate_finding,
)
