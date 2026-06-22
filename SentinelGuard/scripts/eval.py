#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基线结果统计脚本
读取 per_sample.jsonl 文件，计算二分类指标并输出摘要。
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
RESULTS_FILE = Path("./eval_outputs/per_sample.jsonl")  # 基线结果文件路径
OUTPUT_FILE = Path("./eval_outputs/summary1.json")  # 输出摘要路径


def load_results(filepath: Path) -> List[Dict[str, Any]]:
    """读取 JSONL 文件，返回有效样本列表"""
    samples = []
    with filepath.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                # 只保留有有效预测的样本
                if "pred" in rec and rec["pred"] is not None:
                    samples.append(rec)
            except json.JSONDecodeError:
                continue
    return samples


def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    """根据真实标签和预测标签计算指标"""
    if not y_true:
        return {}

    metrics = {
        "total_samples": len(y_true),
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }

    # 若两类都存在，计算 AUC（使用预测标签作为分数）
    if len(set(y_true)) > 1:
        try:
            metrics["roc_auc"] = roc_auc_score(y_true, y_pred)
        except Exception:
            metrics["roc_auc"] = None
    else:
        metrics["roc_auc"] = None

    return metrics


def main():
    if not RESULTS_FILE.exists():
        print(f"❌ 结果文件不存在: {RESULTS_FILE}")
        return

    samples = load_results(RESULTS_FILE)
    print(f"✅ 成功加载 {len(samples)} 个有效样本")

    y_true = [s["label"] for s in samples]
    y_pred = [s["pred"] for s in samples]

    metrics = compute_metrics(y_true, y_pred)

    # 打印到控制台
    print("\n========== 基线评估摘要 ==========")
    print(f"样本总数: {metrics.get('total_samples', 0)}")
    print(f"准确率:   {metrics.get('accuracy', 'N/A'):.4f}")
    print(f"查准率:   {metrics.get('precision', 'N/A'):.4f}")
    print(f"召回率:   {metrics.get('recall', 'N/A'):.4f}")
    print(f"F1 分数:  {metrics.get('f1', 'N/A'):.4f}")
    print(f"AUC:      {metrics.get('roc_auc', 'N/A')}")

    cm = metrics.get("confusion_matrix", [])
    if cm:
        print("混淆矩阵:")
        print(f"           预测良性  预测钓鱼")
        print(f"实际良性    {cm[0][0]:>5}      {cm[0][1]:>5}")
        print(f"实际钓鱼    {cm[1][0]:>5}      {cm[1][1]:>5}")

    # 保存到 JSON 文件
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    print(f"\n📊 摘要已保存至: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()