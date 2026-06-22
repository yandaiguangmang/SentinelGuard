#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从原始数据集中随机抽取 500 条样本（250 phishing + 250 benign），
将 HTML 文件和精简后的 index.sql 复制到目标目录，
供评估脚本直接使用，无需修改评估代码。
"""

from __future__ import annotations

import random
import re
import shutil
from pathlib import Path
from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# 原始数据路径（可根据实际情况修改）
# ---------------------------------------------------------------------------
ORIGINAL_INDEX_SQL = Path(r"F:\url_dataset\index.sql")
ORIGINAL_HTML_DIR = Path(r"F:\url_dataset\dataset\dataset-part-1")

# 输出目录（相对于项目根，或写绝对路径）
OUTPUT_DIR = Path("data")
OUTPUT_HTML_DIR = OUTPUT_DIR / "html"  # 存放 HTML 文件
OUTPUT_INDEX_SQL = OUTPUT_DIR / "index.sql"

# 抽样参数
SAMPLE_SIZE_PER_CLASS = 100
RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# 解析原始 index.sql（复用评估脚本中的正则）
# ---------------------------------------------------------------------------
INDEX_ROW_RE = re.compile(
    r"""\(\s*(\d+)\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(0|1)\s*,\s*'([^']*)'\s*\)"""
)


def parse_index_sql(path: Path) -> List[Dict[str, Any]]:
    """解析原始 index.sql，返回样本列表（保持原有字段）。"""
    text = path.read_text(encoding="utf-8", errors="ignore")
    rows = []
    for m in INDEX_ROW_RE.finditer(text):
        rows.append(
            {
                "id": int(m.group(1)),
                "url": m.group(2),
                "website": m.group(3),  # HTML 文件名
                "label": int(m.group(4)),
                "created_at": m.group(5),
            }
        )
    if not rows:
        # 备用：可能跨行的解析
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


def main():
    random.seed(RANDOM_SEED)

    # 1. 加载全部数据
    print("Parsing original index.sql ...")
    all_rows = parse_index_sql(ORIGINAL_INDEX_SQL)
    if not all_rows:
        print("Error: No rows found in index.sql")
        return

    # 2. 按 label 分组
    benign = [r for r in all_rows if r["label"] == 0]
    phishing = [r for r in all_rows if r["label"] == 1]
    print(f"Total samples: {len(all_rows)} (benign: {len(benign)}, phishing: {len(phishing)})")

    # 3. 随机抽样
    n_benign = min(len(benign), SAMPLE_SIZE_PER_CLASS)
    n_phishing = min(len(phishing), SAMPLE_SIZE_PER_CLASS)
    sampled_benign = random.sample(benign, n_benign)
    sampled_phishing = random.sample(phishing, n_phishing)
    sampled = sampled_benign + sampled_phishing
    random.shuffle(sampled)  # 打乱顺序
    print(f"Sampled {len(sampled)} rows (benign: {n_benign}, phishing: {n_phishing})")

    # 4. 准备输出目录
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_HTML_DIR.mkdir(parents=True, exist_ok=True)

    # 5. 复制 HTML 文件
    missing_html = 0
    for row in sampled:
        website = row["website"]
        src = ORIGINAL_HTML_DIR / website
        dst = OUTPUT_HTML_DIR / website
        if src.exists():
            shutil.copy2(src, dst)
        else:
            missing_html += 1
            print(f"Warning: Missing HTML file {src}")

    if missing_html:
        print(f"Warning: {missing_html} HTML files not found (likely already absent in original)")

    # 6. 生成新的 index.sql
    # 保持原有格式：INSERT INTO table VALUES (id, url, website, label, created_at), ...
    lines = []
    for row in sampled:
        # 转义单引号
        url = row["url"].replace("'", "\\'")
        website = row["website"].replace("'", "\\'")
        created_at = row["created_at"].replace("'", "\\'")
        lines.append(
            f"({row['id']}, '{url}', '{website}', {row['label']}, '{created_at}')"
        )

    insert_statement = "INSERT INTO dataset VALUES\n" + ",\n".join(lines) + ";"

    OUTPUT_INDEX_SQL.write_text(insert_statement, encoding="utf-8")

    print(f"\nSample dataset created at {OUTPUT_DIR}")
    print(f" - HTML files: {OUTPUT_HTML_DIR}")
    print(f" - Index SQL:   {OUTPUT_INDEX_SQL}")
    print("You can now run the evaluation script by pointing:")
    print(f"  INDEX_SQL_PATH = r'{OUTPUT_INDEX_SQL}'")
    print(f"  HTML_DIR = r'{OUTPUT_HTML_DIR}'")


if __name__ == "__main__":
    main()