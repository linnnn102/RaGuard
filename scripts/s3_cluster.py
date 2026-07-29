#!/usr/bin/env python3
"""s3_cluster.py — S3: validate the 3-task hypothesis by clustering.

Embeds each curated training example (reusing the nomic embedder via
``KnowledgeBase.embed_query`` with the ``search_query:`` prefix) and runs
KMeans. We are *validating* that the three declared tasks form three natural
clusters, not discovering unknown structure — so k=3 is the headline run, with a
k=2..6 silhouette sweep to show the knee at 3, plus a cluster-vs-task cross-tab.

Outputs:
  * results/reports/s3_cluster_report.json  (silhouette sweep + cross-tab)
  * results/reports/s3_cluster_pca.png      (PCA scatter coloured by task)

Heavy deps (numpy, sklearn, matplotlib, sentence-transformers) are imported
lazily inside main so the file imports anywhere.

Usage:
    python scripts/s3_cluster.py [--train-dir data/train] [--k 3]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASKS = ["analyze_code", "select_wordlists", "suggest_mitigations"]


def _load_examples(train_dir: Path):
    texts, labels = [], []
    for task in TASKS:
        path = train_dir / f"{task}.curated.jsonl"
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            # Represent an example by its user prompt (the task-shaped input).
            texts.append(row.get("user", "")[:2000])
            labels.append(task)
    return texts, labels


def main():
    p = argparse.ArgumentParser(description="S3 clustering — validate 3 task boundaries")
    p.add_argument("--train-dir", type=Path, default=PROJECT_ROOT / "data/train")
    p.add_argument("--k", type=int, default=3, help="Headline cluster count (default 3)")
    p.add_argument("--k-min", type=int, default=2)
    p.add_argument("--k-max", type=int, default=6)
    p.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "results/reports")
    args = p.parse_args()

    import numpy as np
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score
    from sklearn.decomposition import PCA

    # Reuse the project's embedder.
    import sys
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

    texts, labels = _load_examples(args.train_dir)
    if len(texts) < args.k_max + 1:
        raise SystemExit(
            f"[s3] Only {len(texts)} curated examples found in {args.train_dir}. "
            "Run the pipeline + s2_curate.py to generate more first."
        )

    # Same local Ollama embedder the KB uses — no HuggingFace Hub call and no
    # trust_remote_code, so S3 stays offline like the rest of the pipeline.
    from embedders import OllamaEmbedder

    embedder = OllamaEmbedder()
    emb = np.asarray(
        embedder.encode(texts, is_query=True, normalize_embeddings=True, progress_every=4)
    )

    # Silhouette sweep.
    sweep = {}
    for k in range(args.k_min, args.k_max + 1):
        km = KMeans(n_clusters=k, n_init=10, random_state=0).fit(emb)
        sweep[k] = round(float(silhouette_score(emb, km.labels_)), 4)

    # Headline k clustering + cross-tab against task labels.
    km = KMeans(n_clusters=args.k, n_init=10, random_state=0).fit(emb)
    crosstab: dict[str, dict[str, int]] = {}
    for task, cluster in zip(labels, km.labels_):
        crosstab.setdefault(task, {})
        crosstab[task][str(int(cluster))] = crosstab[task].get(str(int(cluster)), 0) + 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "n_examples": len(texts),
        "k_headline": args.k,
        "silhouette_sweep": sweep,
        "best_k": max(sweep, key=sweep.get),
        "cluster_vs_task": crosstab,
    }
    report_path = args.out_dir / "s3_cluster_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n[s3] report -> {report_path}")

    # PCA scatter, coloured by true task.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        pca = PCA(n_components=2, random_state=0).fit_transform(emb)
        plt.figure(figsize=(7, 6))
        for task in TASKS:
            idx = [i for i, l in enumerate(labels) if l == task]
            if idx:
                plt.scatter(pca[idx, 0], pca[idx, 1], label=task, alpha=0.7, s=18)
        plt.legend()
        plt.title(f"S3 — curated examples in embedding space (k={args.k})")
        png = args.out_dir / "s3_cluster_pca.png"
        plt.savefig(png, dpi=120, bbox_inches="tight")
        print(f"[s3] scatter -> {png}")
    except Exception as e:  # noqa: BLE001
        print(f"[s3] PCA plot skipped: {e}")


if __name__ == "__main__":
    main()
