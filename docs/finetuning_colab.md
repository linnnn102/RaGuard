# S5 — Fine-tuning a 1.7B specialist on Colab

How to shrink a specialist from the `qwen3:8b` off-the-shelf model to a
**fine-tuned `qwen3:1.7b` LoRA adapter** that matches it on one narrow task —
the payoff step of the S1→S6 flywheel (arXiv:2506.02153). The GPU work runs on
Colab; the repo half (`export_dataset.py`, `register_adapter.py`) stays local.

This is **knowledge distillation**: the teacher is the `qwen3:8b` (or GLM5)
specialist that produced your S1 logs; the student is the 1.7B that learns to
reproduce the teacher's JSON output *given the same RAG-grounded prompt*. The
1.7B still calls the RAG at inference — retrieval stays in the prompt, only the
generator shrinks. It also composes with Move 1: `format: json` keeps the small
student's output valid while it learns the task.

---

## 0. The real constraint: you need more data, not more GPU

After `s2_curate.py` + `export_dataset.py` on the current logs:

| Task | Raw S1 calls | Unique after dedup | Verdict |
|---|---|---|---|
| `analyze_code` | 120 | **28** | Enough to *demonstrate*, too few to *beat* 8B |
| `suggest_mitigations` | 132 | **85** | Workable for a first adapter |
| `select_wordlists` | 0 | 0 | No data — skip (it has a static-map fallback) |

The `analyze_code` dedup dropped 90/120 because the same 2–3 files were scanned
repeatedly. **Fine-tuning on 28 examples will lock in the JSON format but won't
lift accuracy** — the model just memorizes. Before Colab, grow the set:

```bash
# Run the 8B (or GLM5) teacher over a DIVERSE corpus of Python files so S1 logs
# accumulate varied (function, RAG-context) → findings pairs.
for f in corpus/*.py; do python -m agentsec.cli scan "$f"; done
python scripts/s2_curate.py            # re-curate (dedup is automatic)
python scripts/export_dataset.py       # re-export train/val
```

Target **~300–1000 unique** examples per task for a defensible eval win. 28 is
fine for a smoke-test run so you can validate the whole pipeline end to end
first, then scale the data.

---

## 1. Export the dataset (local)

```bash
python scripts/export_dataset.py --task analyze_code
# -> data/export/analyze_code/{train.jsonl, val.jsonl, meta.json}
```

Each row is OpenAI chat format — `{"messages":[system, user, assistant]}` — where
`user` already contains the retrieved CWE/CVE context. Upload the task folder to
Google Drive (or push to a private repo you clone in Colab).

---

## 2. Colab notebook

Runtime → change runtime type → **T4 GPU** (the free tier is enough for 1.7B).

### Cell 1 — install
```python
!pip install -q unsloth
# unsloth pulls a matched torch/transformers/trl/peft/bitsandbytes stack.
```

### Cell 2 — load Qwen3-1.7B in 4-bit
```python
from unsloth import FastLanguageModel

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name   = "unsloth/Qwen3-1.7B",
    max_seq_length = 4096,        # analyze_code prompts are long (RAG context)
    load_in_4bit = True,          # QLoRA — fits T4 16GB with room to spare
    dtype        = None,
)

model = FastLanguageModel.get_peft_model(
    model,
    r = 32, lora_alpha = 32, lora_dropout = 0.0, bias = "none",
    target_modules = ["q_proj","k_proj","v_proj","o_proj",
                      "gate_proj","up_proj","down_proj"],
    use_gradient_checkpointing = "unsloth",
    random_state = 3407,
)
```

### Cell 3 — load the exported data and apply the chat template
```python
from datasets import load_dataset

data = load_dataset("json", data_files={
    "train":      "/content/drive/MyDrive/analyze_code/train.jsonl",
    "validation": "/content/drive/MyDrive/analyze_code/val.jsonl",
})

def to_text(ex):
    # enable_thinking=False: our targets are plain JSON, no <think> block.
    return {"text": tokenizer.apply_chat_template(
        ex["messages"], tokenize=False, add_generation_prompt=False,
        enable_thinking=False)}

data = data.map(to_text, remove_columns=["messages"])
```

### Cell 4 — train (loss on the assistant JSON only)
```python
from trl import SFTTrainer, SFTConfig
from unsloth.chat_templates import train_on_responses_only

trainer = SFTTrainer(
    model = model, tokenizer = tokenizer,
    train_dataset = data["train"], eval_dataset = data["validation"],
    args = SFTConfig(
        dataset_text_field = "text",
        max_seq_length = 4096,
        per_device_train_batch_size = 1,
        gradient_accumulation_steps = 8,     # effective batch 8
        num_train_epochs = 3,                # 3–5 for small sets
        learning_rate = 2e-4,
        lr_scheduler_type = "cosine",
        warmup_ratio = 0.05,
        optim = "adamw_8bit",
        logging_steps = 5,
        seed = 3407,
        output_dir = "outputs",
    ),
)

# Mask the prompt so the model is graded only on producing the findings JSON —
# the single biggest quality lever when data is scarce.
trainer = train_on_responses_only(
    trainer,
    instruction_part = "<|im_start|>user\n",
    response_part    = "<|im_start|>assistant\n",
)

trainer.train()
```

### Cell 5 — sanity check before exporting
```python
FastLanguageModel.for_inference(model)
msgs = data["validation"][0]["text"]  # or build a fresh prompt
# generate and eyeball that it returns a valid JSON array — not prose, no <think>.
```

---

## 3. Get it into Ollama

### Path A — GGUF LoRA adapter (matches `register_adapter.py`, zero code change)
```python
model.save_pretrained("lora_adapter")            # adapter_config.json + safetensors
tokenizer.save_pretrained("lora_adapter")

!git clone --depth 1 https://github.com/ggerganov/llama.cpp
!python llama.cpp/convert_lora_to_gguf.py lora_adapter \
        --base unsloth/Qwen3-1.7B --outfile adapter.gguf
```
Download `adapter.gguf`, then on the host:
```bash
python scripts/register_adapter.py --task analyze_code --version v2 \
       --print-modelfile --base qwen3:1.7b        # writes adapters/analyze_code/v2/Modelfile
cp ~/Downloads/adapter.gguf adapters/analyze_code/v2/
python scripts/register_adapter.py --task analyze_code --version v2
# -> ollama create qwen3-analyze-code-v2
```

### Path B — merged GGUF (fallback if adapter conversion fights you)
```python
model.save_pretrained_gguf("qwen3-analyze", tokenizer, quantization_method="q4_k_m")
# writes qwen3-analyze/*.Q4_K_M.gguf and a ready Modelfile
```
This bakes the LoRA into a standalone model. The Modelfile is
`FROM ./qwen3-analyze.Q4_K_M.gguf` (no `ADAPTER` line) — hand-write it or edit
the one `register_adapter.py` scaffolds, then `ollama create qwen3-analyze-code-v2 -f Modelfile`.

---

## 4. Wire it in (S6) and measure

One-line config swap — no code change (the registry routes by tag):

```yaml
# config/agentsec.yaml
tasks:
  analyze_code:
    backend: ollama
    model: qwen3-analyze-code-v2     # was qwen3:8b
    format: json                     # Move 1 — keep the JSON guarantee
    options: { num_predict: 2048 }
```

Then compare against the 8B baseline (this is your thesis result):
```bash
python eval/run_eval.py     # latency · tokens · price · F1, tuned vs baseline
```
Roll back instantly by setting `model:` back to `qwen3:8b` — the S4 pivot.

---

## Resource summary

| | Hardware | VRAM | Time (per task) | Cost |
|---|---|---|---|---|
| Qwen3-1.7B QLoRA | free Colab **T4** | ~6–9 GB | ~10–30 min | **$0** |
| Qwen3-4B QLoRA | T4 / Colab Pro | ~10–13 GB | ~20–45 min | $0–2 |
| Qwen3-8B QLoRA | T4 (seq 2048) / A100 | ~14–16 GB | ~45–90 min | $0–5 |

Compute is not the constraint — a 1.7B adapter costs a coffee break on the free
tier. **The work is in the data**: get to a few hundred diverse, curated
examples per task, and the fine-tune is the easy part.
```
