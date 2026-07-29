"""reporting.py — report writers, reused verbatim from vuln_scanner.

Re-exported (not rewritten) so the ``results[].findings[]`` schema with
``line_start`` / ``line_end`` stays byte-identical — that layout is the contract
``generate_fuzz_script.py`` depends on. Imported lazily to keep this module
import-light.
"""

from __future__ import annotations


def save_json_report(*args, **kwargs):
    from vuln_scanner import save_json_report as _impl
    return _impl(*args, **kwargs)


def print_report(*args, **kwargs):
    from vuln_scanner import print_report as _impl
    return _impl(*args, **kwargs)
