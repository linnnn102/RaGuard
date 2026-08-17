# RaGuard — experiment design

Empirically testing the claims of *SLMs are the Future of Agentic AI*
([arXiv:2506.02153](https://arxiv.org/abs/2506.02153)) in the RaGuard security
domain. Everything here extends the existing harness (`eval/run_eval.py`,
`eval/labels/`), it does not replace it.

## 0. The claims under test

| # | Paper's position | What we must show in RaGuard |
|---|---|---|
| C1 | SLMs are **capable enough** for agentic subtasks | a small *fine-tuned* specialist matches the large model on each security task |
| C2 | SLMs are **more economical** (latency, cost, energy, params) | the specialist is Pareto-better on cost/latency at equal quality |
| C3 | The **LLM→SLM conversion algorithm** (S1–S6) works | the heterogeneous system ≈ all-LLM baseline end-to-end, far cheaper |

The whole point of the S4 config router is that **one variable — model routing —
changes between conditions while everything else (prompts, RAG KB, test set,
fuzzer) is held fixed.** That is the controlled experiment.

## 1. Research questions → experiments

| RQ | Question | Experiment | Level |
|---|---|---|---|
| RQ1 | Does a small **fine-tuned** specialist match the large model on the task? | model comparison on held-out test set | per-task (component) |
| RQ2 | How much cheaper / faster is it? | efficiency measurement, same runs as RQ1 | per-task |
| RQ3 | Does the **converted system** match the all-LLM baseline end-to-end? | the 3-arm pipeline eval | system |
| RQ4 | *What* drives the result? | ablations (fine-tuning, RAG, structured output, size, teacher, data) | component |
| RQ5 | Does **dynamic fuzz-confirmation** improve precision? | static vs confirmed findings | system (RaGuard's own contribution) |

## 2. Conditions (the "arms")

Each is one `config/*.yaml`; the router does the rest.

| Arm | analyze_code / specialists | Orchestrator | Role |
|---|---|---|---|
| `teacher` | Kimi K2.7-code (cloud) | — | quality upper bound / label source |
| `baseline` (arm 1) | qwen3:8b for **every** task, fixed order | qwen3:8b | the "one big LLM does all" strawman the paper attacks |
| `ots` (arm 2) | off-the-shelf qwen3:1.7b, **untuned** | qwen3:8b (or GLM5) | naive shrink — expected to be weak |
| `tuned` (arm 3) | qwen3:1.7b + **LoRA adapter** | qwen3:8b (or GLM5) | the paper's payoff — **the headline result** |

The headline the thesis is trying to earn: **arm 3 ≈ arm 1 on quality, ≪ on
cost/latency, and ≫ arm 2** (i.e. fine-tuning, not just shrinking, is what makes
it work).

## 3. Datasets — the make-or-break

Two **disjoint** sets. Getting this wrong invalidates everything.

- **Training corpus** — teacher-labeled (Kimi), used only to fine-tune the
  specialist. This is what `build_corpus.py` is producing now (dsvw, pygoat,
  vulpy, dvpwa + benign libs).
- **Held-out test set** — **human-verified** gold labels, used only to score.
  Format already exists (`eval/labels/*.labels.json`: `expected_findings`,
  `expected_clean`, `expected_dynamic_confirmation`).

Two rules that protect the result:
1. **No leakage.** Test targets must come from repos/files **not** in the
   training corpus. Hold out whole repos (e.g. train on dsvw+pygoat+vulpy,
   *never scan* the held-out apps) so no function crosses over.
2. **Gold ≠ teacher.** Eval labels are hand-verified, because the teacher is
   itself one of the things under test — scoring against teacher output would
   just measure imitation, not correctness.

**Held-out set status:** the gold set is still small (`orders_api` +
`vuln_dashboard` + `test_target2`). Target **~20–30 held-out functions, ~50–100
gold findings, plus matched benign functions**. `scripts/make_label_stub.py`
scaffolds new ones. This remains the highest-priority *eval* build item.

### Training-corpus status and a stated limitation

As of 2026-08-17 the Muse-labeled corpus holds **2,470 unique functions** (494% of
the 500 target), with **3 core CWEs at depth** (CWE-89 ×23, CWE-22 ×25, CWE-306
×44) and **520 findings across 176 further CWE classes** — but 12/15 of the
*declared* core CWEs sit under 20 examples, and the benign share is **81%**.

Two things follow, and both belong in the write-up:

1. **Long-tail CWE scarcity is a property of the data, not a collection failure.**
   Real-world Python code contains XXE, SSTI, and eval-injection far more rarely
   than SQL injection or path traversal. Scanning more code does not fix the
   distribution; manufacturing more synthetic fixtures would teach the student
   *fixture* patterns rather than real vulnerabilities. So the experiments are
   **scoped to the CWEs with genuine depth**, and the scarcity is reported as a
   finding. (Compare PrimeVul's critique of label noise in earlier vuln
   benchmarks — dataset quality is a known confound in this field.)
2. **Teacher label-id drift.** Muse frequently assigns a parent/sibling CWE
   (CWE-20, CWE-352, …) where the answer key expects a specific child, which is
   why 176 "other" classes appear. Some apparent gaps are *mislabeled*, not
   missing — so per-CWE counts understate true coverage, and detection recall is
   the more trustworthy metric than CWE-id match.

The **81% benign skew is corrected at export**, not by more labeling:
`export_dataset.py --max-benign-frac 0.45` deterministically drops surplus benign
rows (~470 vulnerable + ~385 benign ≈ **855 balanced examples**). Training on the
raw 81% would teach the model to answer "no vulnerability" by default.

**Future work:** building a long-tail-CWE Python dataset is a project in its own
right (see PyVul / SecurityEval as starting points).

## 4. Metrics

**Quality** (from the vuln report vs gold labels):
- precision / recall / **F1** on `(function, cwe_id)` detection — harness has this
- **per-CWE** breakdown — which weaknesses the small model keeps vs drops
- **benign accuracy / false-positive rate** on `expected_clean` — *not yet
  scored*; this is the precision story (does the shrunk model over-flag?)
- **valid-JSON rate** — for the structured-output ablation (RQ4c)
- mitigation validity (parses + non-empty `fixed_code`) — harness has this

**Efficiency** (from S1 call logs, harness has these):
- latency per task (p50/p95) and end-to-end
- prompt/completion **tokens**, and **USD** (local = \$0; cloud priced)
- **params / energy proxy** for the C2 claim: model parameter count, and GPU
  power via `nvidia-smi --query-gpu=power.draw` sampled during a run (or FLOPs
  ≈ 2·params·tokens). The paper leans on energy — worth one clean number.

## 5. The experiments in detail

### RQ1 — per-task capability (the core result)
Run `analyze_code` alone over the held-out test set for each model
(`teacher`, qwen3:8b, qwen3:1.7b-ots, qwen3:1.7b-tuned; optionally a 4b rung).
Score F1 + per-CWE + benign-FP. **Expected:** tuned-1.7b ≈ 8b ≈ teacher; ots-1.7b
well below. Repeat for `suggest_mitigations` (score by validity + an LLM-judge
rubric) and `select_wordlists` (catalog-match accuracy).

### RQ2 — economy
Same runs as RQ1; report latency, tokens, USD, params, energy. Plot the
**quality-vs-cost frontier** (F1 on y, cost/latency on x). The tuned SLM should
sit top-left (Pareto-dominant). This *is* the C2 evidence.

### RQ3 — system-level conversion
`run_eval.py --run` over the test set for arms 1/2/3 end-to-end (analyze → fuzz →
mitigate). Report end-to-end F1, latency, tokens, USD, fuzz-confirmation rate.
**Expected:** arm 3 matches arm 1 quality at a fraction of the cost; arm 2 lags.

### RQ4 — ablations (isolate the cause)
| Ablation | Toggle | Question |
|---|---|---|
| a. fine-tuning | ots vs tuned | does tuning (not just size) close the gap? |
| b. RAG grounding | `top_k>0` vs RAG-off | does retrieval matter; does tuning internalize knowledge? |
| c. structured output (Move 1) | `format: json` on/off on 1.7b | does it fix the JSON-holding failure? (valid-JSON rate) |
| d. size sweep | 0.6b/1.7b/4b/8b × {ots, tuned} | the capability-vs-size curve; where tuning wins |
| e. teacher quality | student ← Kimi vs ← qwen3:8b labels | does a stronger teacher yield a better student? |
| f. data size | F1 vs #training examples | learning curve — how much labeled data you actually need |

Each is a config swap (S4) except (e)/(f), which need extra fine-tune runs.

### RQ5 — dynamic confirmation (RaGuard's own contribution)
Compare precision of **static** findings vs findings **after fuzz-confirmation**
(`expected_dynamic_confirmation`). Does confirming with the fuzzer cut false
positives? This is the piece that goes beyond the paper.

## 6. Statistical rigor

- LLMs are stochastic (Kimi requires temperature 1). Run each condition
  **3–5×**, report **mean ± std**. The core arms are local → repeats are free.
- Small test set → report **bootstrap 95% CIs** on F1, and use **paired**
  comparisons (same targets across arms) with a sign / Wilcoxon test.
- Fix seeds where the backend allows; log every run's raw numbers.

## 7. Build checklist (extends `run_eval.py`)

- [ ] **Expand the gold test set** to ~20–30 held-out functions (highest priority)
- [ ] Create `config/agentsec.v2.yaml` (tuned) once the LoRA adapter is registered
- [ ] Add **benign false-positive** scoring (`expected_clean` is unused today)
- [ ] Add **per-CWE** breakdown and **valid-JSON rate** to scoring
- [ ] Add **repeats + mean±std** (and bootstrap CI) to the harness
- [ ] Add a **size-sweep / ablation** driver (loops configs, one row each)
- [ ] Add an **energy/params** column (nvidia-smi sampling or params proxy)

## 8. Execution order (dependency chain)

```
finish corpus labeling (Kimi)  ─┐
                                ├─▶ fine-tune 1.7b (Colab) ─▶ register adapter ─▶ config/agentsec.v2.yaml ─┐
build held-out gold test set ──┘                                                                          ├─▶ run RQ1–RQ5
                                                                                                          ┘
```
The eval can't produce the headline until the tuned adapter exists **and** the
test set is built — so those two are the critical path; start the test set now,
in parallel with labeling.
