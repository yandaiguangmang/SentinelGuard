#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phishing Websites Dataset evaluation pipeline — integrated with SentinelGuard modules.
Runs offline static analysis + optional deep/multi‑agent analysis.

Edit the hard‑coded constants below to point to your local dataset.
"""

from __future__ import annotations

import html as html_lib
import html.parser
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# -----------------------------------------------------------------------------
# Hard‑coded parameters – adjust these for your environment
# -----------------------------------------------------------------------------
INDEX_SQL_PATH = Path(r"F:\url_dataset\index.sql")          # Path to index.sql
HTML_DIR = Path(r"F:\url_dataset\dataset\dataset-part-1")                 # Directory containing *.html files
OUTPUT_DIR = Path("./eval_outputs")                  # Where to save results
SAMPLE_LIMIT: Optional[int] = 2                    # Only evaluate first N samples
THRESHOLD = 50                                       # Score threshold for phishing (0‑100)

# -----------------------------------------------------------------------------
# SentinelGuard imports – make sure the project root is on sys.path
# -----------------------------------------------------------------------------
try:
    from SentinelGuard.state import (
        AnalysisRuntimeConfig,
        DetectionFinding,
        DetectionReport,
    )
    from SentinelGuard.parsers.input_parser import parse_target
    from SentinelGuard.analyzers.url_analyzer import analyze_url
except ImportError:
    raise

try:
    from SentinelGuard.analyzers.url_deep_analyzer import deep_analyze_url
    DEEPRUN_AVAILABLE = True
except ImportError:
    deep_analyze_url = None
    DEEPRUN_AVAILABLE = False

# -----------------------------------------------------------------------------
# Local offline page parser (remains because project expects live page fetch)
# -----------------------------------------------------------------------------

SENSITIVE_KEYWORDS = (
    "login", "verify", "secure", "account", "bank", "wechat", "alipay",
    "password", "signin", "wallet", "支付", "登录", "验证", "账号",
)

DOWNLOAD_EXTENSIONS = (".apk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".zip", ".rar")

MAX_BODY_BYTES = 200_000
PAGE_TEXT_EXCERPT_LIMIT = 800
HTML_EXCERPT_LIMIT = 1200


class PageSignalParser(html.parser.HTMLParser):
    """Extract key signals from static HTML content."""

    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._in_title = False
        self.visible_text_parts: List[str] = []
        self.password_forms = 0
        self.hidden_inputs = 0
        self.meta_refresh: List[str] = []
        self.script_srcs: List[str] = []
        self.form_actions: List[str] = []
        self.download_links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "input":
            input_type = attr_map.get("type", "").lower()
            if input_type == "password":
                self.password_forms += 1
            if input_type == "hidden":
                self.hidden_inputs += 1
        elif tag == "meta" and attr_map.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh.append(attr_map.get("content", ""))
        elif tag == "script" and attr_map.get("src"):
            self.script_srcs.append(attr_map["src"])
        elif tag == "form":
            self.form_actions.append(attr_map.get("action", ""))
        elif tag == "a" and attr_map.get("href", "").lower().endswith(DOWNLOAD_EXTENSIONS):
            self.download_links.append(attr_map["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        text = (data or "").strip()
        if text:
            self.visible_text_parts.append(text)
        if self._in_title:
            self.title += text

    def summary(self) -> Dict[str, Any]:
        visible_text = " ".join(self.visible_text_parts)
        visible_text = re.sub(r"\s+", " ", visible_text).strip()
        return {
            "title": self.title[:120],
            "visible_text_excerpt": visible_text[:PAGE_TEXT_EXCERPT_LIMIT],
            "password_forms": self.password_forms,
            "hidden_inputs": self.hidden_inputs,
            "meta_refresh": self.meta_refresh[:5],
            "script_srcs": self.script_srcs[:20],
            "form_actions": self.form_actions[:10],
            "download_links": self.download_links[:10],
            "external_script_count": len([s for s in self.script_srcs if s.startswith(("http://", "https://", "//"))]),
        }


def build_page_summary_from_html(html_text: str) -> Dict[str, Any]:
    parser = PageSignalParser()
    parser.feed(html_text)
    summary = parser.summary()
    html_excerpt = re.sub(r"\s+", " ", html_lib.unescape(html_text))[:HTML_EXCERPT_LIMIT]
    summary["html_summary"] = {
        "raw_excerpt": html_excerpt,
        "text_excerpt": summary.get("visible_text_excerpt", ""),
    }
    summary["final_url"] = ""
    summary["fetch_mode"] = "offline_html"
    summary["proxy_used"] = False
    summary["content_type"] = "text/html"
    summary["status_code"] = 200
    return summary


def analyze_page_summary(page_summary: Dict[str, Any]) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if not page_summary:
        return findings

    if page_summary.get("password_forms", 0) > 0:
        findings.append(DetectionFinding(
            "PAGE_PASSWORD_FORM",
            "页面包含密码输入框",
            "high",
            "页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。",
            f"密码框数量: {page_summary['password_forms']}",
            "仅在确认域名归属和证书可信后输入账号密码。",
        ))
    if page_summary.get("hidden_inputs", 0) >= 5:
        findings.append(DetectionFinding(
            "PAGE_MANY_HIDDEN_INPUTS",
            "隐藏表单字段较多",
            "medium",
            "页面包含较多隐藏字段，可能用于追踪、表单伪造或复杂登录流程。",
            f"隐藏字段数量: {page_summary['hidden_inputs']}",
            "结合表单提交地址核验页面真实性。",
        ))
    if page_summary.get("meta_refresh"):
        findings.append(DetectionFinding(
            "PAGE_META_REFRESH",
            "页面包含自动跳转指令",
            "medium",
            "Meta refresh 可在用户无感知情况下跳转到其他页面。",
            "; ".join(page_summary["meta_refresh"]),
            "关注浏览器最终地址栏域名是否发生变化。",
        ))
    if page_summary.get("download_links"):
        findings.append(DetectionFinding(
            "PAGE_DOWNLOAD_LINK",
            "页面包含可疑下载链接",
            "high",
            "页面包含可执行文件、脚本或压缩包下载入口。",
            ", ".join(page_summary["download_links"][:5]),
            "不要直接打开下载文件，应先在隔离环境中检测。",
        ))
    if page_summary.get("external_script_count", 0) >= 8:
        findings.append(DetectionFinding(
            "PAGE_MANY_EXTERNAL_SCRIPTS",
            "外链脚本数量较多",
            "low",
            "页面加载大量外部脚本，供应链和追踪风险更高。",
            f"外链脚本数量: {page_summary['external_script_count']}",
            "在安全浏览器或隔离环境中访问未知页面。",
        ))
    return findings


# -----------------------------------------------------------------------------
# Dataset loading (unchanged)
# -----------------------------------------------------------------------------

INDEX_ROW_RE = re.compile(
    r"""\(\s*(\d+)\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(0|1)\s*,\s*'([^']*)'\s*\)"""
)


def parse_index_sql(index_sql_path: Path) -> List[Dict[str, Any]]:
    text = index_sql_path.read_text(encoding="utf-8", errors="ignore")
    rows: List[Dict[str, Any]] = []
    for m in INDEX_ROW_RE.finditer(text):
        rows.append({
            "id": int(m.group(1)),
            "url": m.group(2),
            "website": m.group(3),
            "label": int(m.group(4)),
            "created_at": m.group(5),
        })
    if rows:
        return rows

    # Fallback: CSV‑like line parsing
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        m = INDEX_ROW_RE.search(line)
        if m:
            rows.append({
                "id": int(m.group(1)),
                "url": m.group(2),
                "website": m.group(3),
                "label": int(m.group(4)),
                "created_at": m.group(5),
            })
    return rows


def load_html(html_dir: Path, website: str) -> str:
    html_path = html_dir / website
    if not html_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_path}")
    return html_path.read_text(encoding="utf-8", errors="ignore")


# -----------------------------------------------------------------------------
# Build static report leveraging project's URL analyser + offline page signals
# -----------------------------------------------------------------------------

def _json_safe(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        return _json_safe(value.to_dict())
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def score_from_findings(findings: List[DetectionFinding]) -> int:
    if not findings:
        return 0
    severity_weights = {"low": 1, "medium": 3, "high": 6, "critical": 8}
    severity_base = {"low": 5, "medium": 25, "high": 60, "critical": 75}
    cnt: Dict[str, int] = Counter(f.severity for f in findings)
    base = max(severity_base.get(f.severity, 0) for f in findings)
    bonus = sum(cnt.get(sev, 0) * w for sev, w in severity_weights.items())
    return min(100, base + min(20, bonus))


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def build_offline_report(url: str, html_text: str) -> DetectionReport:
    # Reuse project's URL parsing and static URL analysis
    target_ir = parse_target(url, "url")
    config = AnalysisRuntimeConfig()  # no network / LLM needed for static part
    url_analysis = analyze_url(target_ir, fetch_page=False, runtime_config=config)
    url_findings: List[DetectionFinding] = url_analysis["findings"]

    # Supplement with offline HTML page signals
    page_summary = build_page_summary_from_html(html_text)
    page_findings = analyze_page_summary(page_summary)
    all_findings = list(url_findings) + page_findings

    evidence_score = score_from_findings(all_findings)
    risk_level = risk_level_from_score(evidence_score)

    return DetectionReport(
        target_ir=target_ir,
        risk_level=risk_level,
        score=evidence_score,
        findings=all_findings,
        redirect_chain=url_analysis.get("redirect_chain", [url]),
        page_summary=page_summary,
        expert_opinions={},
    )


# -----------------------------------------------------------------------------
# Deep analysis hook
# -----------------------------------------------------------------------------

def run_deep_analysis(report: DetectionReport) -> Optional[Dict[str, Any]]:
    if not DEEPRUN_AVAILABLE or deep_analyze_url is None:
        return None
    try:
        
        # Provide a minimal runtime config; real API keys should be set via env vars
        config = AnalysisRuntimeConfig()
        return deep_analyze_url(report, runtime_config=config)
    except Exception as exc:
        return {"_error": str(exc)}


# -----------------------------------------------------------------------------
# Evaluation metrics
# -----------------------------------------------------------------------------

def prediction_from_static(report: DetectionReport, threshold: int) -> int:
    return int(report.score >= threshold)


def prediction_from_deep(result: Optional[Dict[str, Any]], threshold: int) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    if not result:
        return None, None, "deep_unavailable"
    if "_error" in result:
        return None, None, result["_error"]
    score = result.get("score")
    risk_level = result.get("risk_level")
    if isinstance(score, (int, float)):
        return int(float(score) >= threshold), int(float(score)), None
    if isinstance(risk_level, str):
        return int(risk_level in {"high", "critical"}), None, None
    return None, None, "invalid_deep_output"


def safe_metrics(y_true: List[int], y_pred: List[int], y_score: List[float]) -> Dict[str, Any]:
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred) if y_true else float("nan"),
        "precision": precision_score(y_true, y_pred, zero_division=0) if y_true else float("nan"),
        "recall": recall_score(y_true, y_pred, zero_division=0) if y_true else float("nan"),
        "f1": f1_score(y_true, y_pred, zero_division=0) if y_true else float("nan"),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist() if y_true else [],
    }
    if y_score and len(set(y_true)) > 1:
        try:
            metrics["roc_auc"] = roc_auc_score(y_true, y_score)
        except Exception:
            metrics["roc_auc"] = None
    else:
        metrics["roc_auc"] = None
    return metrics


def summarize_errors(errors: List[str], topk: int = 10) -> List[Tuple[str, int]]:
    return Counter(errors).most_common(topk)


# -----------------------------------------------------------------------------
# Main evaluation driver
# -----------------------------------------------------------------------------

def evaluate_dataset() -> Dict[str, Any]:
    rows = parse_index_sql(INDEX_SQL_PATH)
    if not rows:
        print("No rows parsed from index.sql", file=sys.stderr)
        sys.exit(1)

    if SAMPLE_LIMIT is not None:
        rows = rows[:SAMPLE_LIMIT]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    static_y_true: List[int] = []
    static_y_pred: List[int] = []
    static_y_score: List[float] = []

    deep_y_true: List[int] = []
    deep_y_pred: List[int] = []
    deep_y_score: List[float] = []

    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    started = time.time()

    for idx, row in enumerate(rows, 1):
        url = row["url"]
        website = row["website"]
        label = int(row["label"])

        try:
            html_text = load_html(HTML_DIR, website)
        except Exception as exc:
            errors.append(f"load_html::{website}::{exc}")
            continue

        # Offline static analysis (reuses project modules)
        static_report = build_offline_report(url, html_text)
        static_pred = prediction_from_static(static_report, THRESHOLD)

        # Deep analysis (optional, requires API keys)
        deep_result = run_deep_analysis(static_report)
        deep_pred, deep_score, deep_err = prediction_from_deep(deep_result, THRESHOLD)

        static_y_true.append(label)
        static_y_pred.append(static_pred)
        static_y_score.append(static_report.score / 100.0)

        record: Dict[str, Any] = {
            "id": row["id"],
            "url": url,
            "website": website,
            "label": label,
            "static_score": static_report.score,
            "static_risk_level": static_report.risk_level,
            "static_pred": static_pred,
            "static_findings": [f.to_dict() for f in static_report.findings],
        }

        if deep_result is not None:
            record["deep_result"] = _json_safe(deep_result)
            if deep_err:
                record["deep_error"] = deep_err
                errors.append(f"deep::{website}::{deep_err}")
            else:
                if deep_pred is not None:
                    deep_y_true.append(label)
                    deep_y_pred.append(deep_pred)
                    deep_y_score.append((deep_score or 0) / 100.0)
                record["deep_pred"] = deep_pred
                record["deep_score"] = deep_score

        records.append(record)

        if idx % 50 == 0:
            print(f"[{idx}/{len(rows)}] processed")

    elapsed = time.time() - started

    static_metrics = safe_metrics(static_y_true, static_y_pred, static_y_score)
    deep_metrics = safe_metrics(deep_y_true, deep_y_pred, deep_y_score) if deep_y_true else None

    # Save outputs
    (OUTPUT_DIR / "per_sample.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records),
        encoding="utf-8",
    )

    summary = {
        "dataset_size_requested": len(rows),
        "dataset_size_processed": len(records),
        "threshold": THRESHOLD,
        "deep_available": DEEPRUN_AVAILABLE,
        "elapsed_seconds": elapsed,
        "static_metrics": static_metrics,
        "deep_metrics": deep_metrics,
        "error_summary": summarize_errors(errors),
    }

    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


if __name__ == "__main__":
    result = evaluate_dataset()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\nResults saved to: {OUTPUT_DIR.resolve()}")