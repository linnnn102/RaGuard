# Held-out gold test set

The **human-verified** targets RaGuard is scored against (RQ1–RQ5 in
`docs/experiments.md`). Everything here is deliberately kept **disjoint from the
training corpus** — that separation is what makes the F1 numbers trustworthy.

## The two rules that protect the result

1. **No leakage.** A target here must *not* appear in `config/corpus_sources.yaml`
   and must never be scanned by `build_corpus.py`. Hold out whole files/repos so
   no function the model was fine-tuned on can reappear at test time.
2. **Gold ≠ teacher.** Labels here are decided by a human, not by the Kimi
   teacher. The teacher is one of the things under test — scoring against its
   output would measure imitation, not correctness.

## Layout

```
eval/testset/<name>.py          # the held-out target (this dir)
eval/labels/<name>.labels.json  # its gold labels
```

`orders_api.py` + `eval/labels/orders_api.labels.json` are a worked example:
one SQLi, one command injection, one benign function.

## Label schema

```json
{
  "target": "eval/testset/orders_api.py",
  "description": "one line",
  "expected_findings": [
    {"function": "get_order", "cwe_id": "CWE-89", "cwe_name": "...",
     "min_severity": "HIGH", "line_hint": "the vulnerable line", "notes": "why"}
  ],
  "expected_clean": ["list_orders"],
  "expected_dynamic_confirmation": {"CWE-89": true}
}
```

- **expected_findings** — one entry per true vulnerability. Scored as
  `(function, cwe_id)` pairs → precision / recall / F1, and per-CWE F1.
- **expected_clean** — functions with *no* vulnerability. Any finding on these is
  a false positive → the `benign_acc` metric (does the shrunk model over-flag?).
- **expected_dynamic_confirmation** — which CWEs the fuzzer *should* confirm
  (RQ5). Optional.

## Workflow to add a target

```bash
# 1. Drop a held-out .py in eval/testset/ (must NOT be in the training corpus).
# 2. Generate a label skeleton (lists every function; never overwrites):
python scripts/make_label_stub.py eval/testset/<name>.py
# 3. Edit eval/labels/<name>.labels.json: move each _candidate into
#    expected_findings (add cwe_id) or expected_clean, then delete _candidates.
# 4. Score one arm against it:
python eval/run_eval.py --run --target eval/testset/<name>.py \
    --labels eval/labels/<name>.labels.json \
    --arm baseline=config/agentsec.baseline.yaml --repeats 3
```

## Coverage target

Aim for **~20–30 functions across ~8–12 files**, with:
- **≥2 examples of each core CWE** you claim to detect (89, 79, 78, 22, 94, 502,
  918, 306, 327, …) so per-CWE F1 is meaningful, and
- **a real share of benign functions** (roughly a third) so `benign_acc` /
  false-positive rate has signal.

Two clean ways to source held-out targets without leakage:
- **Hold out a whole repo** from `corpus_sources.yaml` (e.g. reserve `dvpwa`
  purely for eval — never fetch/scan it for training), then label a sample of
  its functions.
- **Curate small fixtures** like `orders_api.py` — fastest for hitting specific
  CWEs and guaranteeing disjointness.
