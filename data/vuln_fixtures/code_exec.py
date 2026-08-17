"""code_exec.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

Code / eval injection patterns (CWE-94 / CWE-95) for the S5 corpus.
"""


def calc(expr):
    return eval(expr)


def apply_rule(code, record):
    exec(code, {"record": record})
    return record


def evaluate_formula(formula, variables):
    return eval(compile(formula, "<formula>", "eval"), {}, variables)


def dynamic_import(module_name):
    return exec(f"import {module_name}")
