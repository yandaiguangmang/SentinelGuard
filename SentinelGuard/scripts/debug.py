#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extract deep analysis prediction errors from per_sample.jsonl.

Outputs: console summary + deep_false_positives.jsonl / deep_false_negatives.jsonl
"""

import json
from pathlib import Path
from typing import Dict, Any, List

# ---------- Configuration ----------
INPUT_JSONL = Path("./eval_outputs/per_sample.jsonl")
OUTPUT_DIR = Path("./eval_outputs/error_analysis")
MAX_EXAMPLES = 10          # Print this many samples per category

# ---------- Helpers ----------

def load_records(jsonl_path: Path) -> List[Dict[str, Any]]:
    records = []
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def extract_deep_errors(records: List[Dict[str, Any]]):
    fp = []   # label=0, deep_pred=1
    fn = []   # label=1, deep_pred=0
    for rec in records:
        if "deep_pred" not in rec or rec["deep_pred"] is None:
            continue
        label = rec["label"]
        pred = rec["deep_pred"]
        if label == 0 and pred == 1:
            fp.append(rec)
        elif label == 1 and pred == 0:
            fn.append(rec)
    return fp, fn


def print_examples(category: str, samples: List[Dict[str, Any]], max_examples: int):
    if not samples:
        print(f"  ✅ No {category} errors.\n")
        return
    print(f"  ❌ {len(samples)} {category} errors. Showing up to {max_examples}:\n")
    for i, rec in enumerate(samples[:max_examples], 1):
        print(f"  --- Example {i} ---")
        print(f"  id      : {rec['id']}")
        print(f"  url     : {rec['url']}")
        print(f"  website : {rec['website']}")
        print(f"  label   : {rec['label']}")
        print(f"  deep_score    : {rec.get('deep_score')}")
        print(f"  deep_pred     : {rec.get('deep_pred')}")
        static_findings = rec.get("static_findings", [])
        if static_findings:
            print("  static_findings (top 3):")
            for f in static_findings[:3]:
                print(f"    - {f.get('rule_id')} ({f.get('severity')}): {f.get('title')}")
        if "deep_error" in rec:
            print(f"  deep_error : {rec['deep_error']}")
        deep_result = rec.get("deep_result", {})
        if isinstance(deep_result, dict):
            summary = deep_result.get("deep_summary")
            if summary:
                print(f"  deep_summary : {summary[:200]}")
        print()
    if len(samples) > max_examples:
        print(f"  ... and {len(samples)-max_examples} more.\n")


def main():
    print("Loading records...")
    records = load_records(INPUT_JSONL)
    print(f"Loaded {len(records)} records.\n")

    deep_fp, deep_fn = extract_deep_errors(records)

    print("=" * 60)
    print("         Deep Analysis Error Analysis")
    print("=" * 60)
    print_examples("False Positive (benign → phishing)", deep_fp, MAX_EXAMPLES)
    print_examples("False Negative (phishing → benign)", deep_fn, MAX_EXAMPLES)

    # Save to files
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, samples in [
        ("deep_false_positives.jsonl", deep_fp),
        ("deep_false_negatives.jsonl", deep_fn),
    ]:
        if not samples:
            continue
        outpath = OUTPUT_DIR / name
        with outpath.open("w", encoding="utf-8") as f:
            for rec in samples:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"  Saved {len(samples)} samples to {outpath}")

    total_deep_preds = len(deep_fp) + len(deep_fn) + sum(
        1 for r in records if "deep_pred" in r and r["deep_pred"] is not None
    ) - len(deep_fp) - len(deep_fn)
    # Just print error counts
    print(f"\nSummary: {len(deep_fp)} false positives, {len(deep_fn)} false negatives")
    print("Done.")


if __name__ == "__main__":
    main()