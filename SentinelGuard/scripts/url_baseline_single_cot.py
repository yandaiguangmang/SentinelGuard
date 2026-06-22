#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单模型离线评估 baseline：将 URL + HTML 送入 gpt-4o-mini 进行钓鱼二分类。
模型在内部进行链式推理，但只输出 `pred: 0` 或 `pred: 1`。
"""

from __future__ import annotations
import re
import tiktoken
from typing import List, Tuple
import json
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from openai import OpenAI
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# ---------------------------------------------------------------------------
# 路径与参数配置（可根据需要修改）
# ---------------------------------------------------------------------------
INDEX_SQL_PATH = Path(r"E:\xinansai\code1\code\SentinelGuard\data\index.sql")
HTML_DIR = Path(r"E:\xinansai\code1\code\SentinelGuard\data\html")
OUTPUT_DIR = Path("./eval_outputs_baseline")
SAMPLE_LIMIT: Optional[int] = 200  # 最多评估多少条
THRESHOLD = 0.5  # 二分类阈值（这里模型直接输出 0/1，不用阈值）

# 模型 API 配置（建议通过环境变量设置，避免硬编码密钥）
API_KEY = os.getenv("OPENAI_API_KEY", "sk-xeSxZRmQN98b2QkBZ6gR725sbVjht9yS9BXU3AQ0J0E289xz")
BASE_URL = os.getenv("OPENAI_BASE_URL", "https://yunwu.ai/v1")
MODEL_NAME = "gpt-4o-mini"

# 并发与请求参数
MAX_WORKERS = 16  # 并发线程数
REQUEST_TIMEOUT = 30  # 单次请求超时（秒）
MAX_RETRIES = 2  # 失败重试次数

# ---------------------------------------------------------------------------
# 提示词模板
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a web security expert. You will be given a URL and the HTML content of the page.
Your task is to determine whether this page is a phishing / malicious page (1) or a benign page (0).

IMPORTANT:
- Think step by step inside your mind, but DO NOT output your reasoning.
- Only output the final prediction on a single line with the format: pred: 0  or  pred: 1
- Do not output anything else."""


def build_user_message(url: str, html_text: str) -> str:
    max_html_len = 8000
    if len(html_text) > max_html_len:
     html_text = html_text[:max_html_len] + "\n... [truncated]"
     
    return f"URL: {url}\n\nHTML:\n{html_text}\n\nPrediction:"


# ---------------------------------------------------------------------------
# 数据集加载（与你的评估脚本相同）
# ---------------------------------------------------------------------------
INDEX_ROW_RE = re.compile(
    r"""\(\s*(\d+)\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(0|1)\s*,\s*'([^']*)'\s*\)"""
)


def parse_index_sql(index_sql_path: Path) -> List[Dict[str, Any]]:
    text = index_sql_path.read_text(encoding="utf-8", errors="ignore")
    rows: List[Dict[str, Any]] = []
    for m in INDEX_ROW_RE.finditer(text):
        rows.append(
            {
                "id": int(m.group(1)),
                "url": m.group(2),
                "website": m.group(3),
                "label": int(m.group(4)),
                "created_at": m.group(5),
            }
        )
    if rows:
        return rows

    # 备选：按行解析
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        m = INDEX_ROW_RE.search(line)
        if m:
            rows.append(
                {
                    "id": int(m.group(1)),
                    "url": m.group(2),
                    "website": m.group(3),
                    "label": int(m.group(4)),
                    "created_at": m.group(5),
                }
            )
    return rows


def load_html(html_dir: Path, website: str) -> str:
    html_path = html_dir / website
    if not html_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_path}")
    return html_path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# 模型调用
# ---------------------------------------------------------------------------
def classify_sample(client: OpenAI, url: str, html_text: str) -> Tuple[Optional[int], str]:
    """返回 (预测值, 错误信息)"""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_message(url, html_text)},
    ]
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0.0,
                max_tokens=10,
                timeout=REQUEST_TIMEOUT,
            )
            content = response.choices[0].message.content.strip()
            # 解析 pred: 0 或 pred: 1
            match = re.search(r"pred:\s*(\d)", content, re.IGNORECASE)
            if match:
                pred = int(match.group(1))
                if pred in (0, 1):
                    return pred, ""
            # 如果没匹配到，尝试检查整个内容是否就是 0 或 1
            if content in ("0", "1"):
                return int(content), ""
            return None, f"unexpected output: '{content[:100]}'"
        except Exception as exc:
            if attempt < MAX_RETRIES:
                time.sleep(1 * (attempt + 1))  # 递增等待
            else:
                return None, str(exc)
    return None, "max retries exceeded"


def process_one(
    row: Dict[str, Any], client: OpenAI, html_dir: Path
) -> Dict[str, Any]:
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=REQUEST_TIMEOUT)
    url = row["url"]
    website = row["website"]
    label = int(row["label"])

    try:
        html_text = load_html(html_dir, website)
    except Exception as exc:
        return {
            "id": row["id"],
            "url": url,
            "label": label,
            "pred": None,
            "error": f"load_html::{website}::{exc}",
        }

    pred, error = classify_sample(client, url, html_text)
    return {
        "id": row["id"],
        "url": url,
        "website": website,
        "label": label,
        "pred": pred,
        "error": error,
    }


# ---------------------------------------------------------------------------
# 指标计算
# ---------------------------------------------------------------------------
def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    if not y_true:
        return {}
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "roc_auc": roc_auc_score(y_true, y_pred)
        if len(set(y_true)) > 1
        else None,
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    rows = parse_index_sql(INDEX_SQL_PATH)
    if not rows:
        print("No rows parsed from index.sql", file=sys.stderr)
        sys.exit(1)

    if SAMPLE_LIMIT is not None:
        rows = rows[:SAMPLE_LIMIT]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

    started = time.time()
    total = len(rows)
    records = []
    errors = []

    # 并发处理
    try:
        from tqdm import tqdm

        HAS_TQDM = True
    except ImportError:
        HAS_TQDM = False

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_row = {
            executor.submit(process_one, row, client, HTML_DIR): row for row in rows
        }

        if HAS_TQDM:
            progress = tqdm(total=total, desc="Processing samples")
        else:
            counter = 0

        for future in as_completed(future_to_row):
            res = future.result()
            records.append(res)
            if res.get("error"):
                errors.append(res["error"])

            if HAS_TQDM:
                progress.update(1)
            else:
                counter += 1
                if counter % 50 == 0:
                    print(f"[{counter}/{total}] processed")

    # 保存逐样本结果
    with open(OUTPUT_DIR / "per_sample1.jsonl", "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # 筛选有效样本
    valid = [r for r in records if r["pred"] is not None]
    if not valid:
        print("No valid predictions!", file=sys.stderr)
        return

    y_true = [r["label"] for r in valid]
    y_pred = [r["pred"] for r in valid]
    metrics = compute_metrics(y_true, y_pred)
    elapsed = time.time() - started

    error_counter = Counter(
        re.sub(r"::.*", "", e) for e in errors
    )  # 只保留错误类型前缀

    summary = {
        "model": MODEL_NAME,
        "dataset_size": len(rows),
        "valid_predictions": len(valid),
        "errors": len(errors),
        "error_summary": error_counter.most_common(10),
        "elapsed_seconds": elapsed,
        "metrics": metrics,
    }

    with open(OUTPUT_DIR / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Results saved to {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()