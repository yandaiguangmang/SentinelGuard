from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Iterable

from SentinelGuard.state import DetectionFinding, DetectionReport


REPORT_DIR = Path("sentinel_reports")


def save_detection_report(report: DetectionReport, output_dir: Path | str = REPORT_DIR) -> DetectionReport:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_type = report.target_ir.target_type or "target"
    safe_mode = report.analysis_mode or "static"
    base_name = f"sentinel_report_{safe_type}_{safe_mode}_{timestamp}"

    html_path = output_path / f"{base_name}.html"
    md_path = output_path / f"{base_name}.md"

    html_path.write_text(render_html_report(report), encoding="utf-8")
    md_path.write_text(render_markdown_report(report), encoding="utf-8")

    report.html_report_path = str(html_path.as_posix())
    report.markdown_report_path = str(md_path.as_posix())
    return report


def render_html_report(report: DetectionReport) -> str:
    ir = report.target_ir
    url = ir.url
    findings = "".join(_finding_card(finding) for finding in report.findings) or "<p>未发现明显风险项。</p>"
    experts = "".join(
        f"<li><strong>{html.escape(role)}</strong>：{html.escape(opinion)}</li>"
        for role, opinion in report.expert_opinions.items()
    )
    redirect_chain = "".join(f"<li>{html.escape(item)}</li>" for item in report.redirect_chain) or "<li>未获取跳转链。</li>"
    placeholders = "".join(
        f"<li><strong>{html.escape(key)}</strong>：{html.escape(value)}</li>"
        for key, value in report.placeholders.items()
    )

    url_block = "<p>该对象不是已实现的网址检测对象。</p>"
    if url:
        url_block = f"""
        <dl>
          <dt>规范化 URL</dt><dd>{html.escape(url.normalized_url)}</dd>
          <dt>协议</dt><dd>{html.escape(url.scheme)}</dd>
          <dt>主机</dt><dd>{html.escape(url.hostname)}</dd>
          <dt>路径</dt><dd>{html.escape(url.path)}</dd>
          <dt>参数数量</dt><dd>{len(url.query_params)}</dd>
        </dl>
        """

    page_summary = _dict_table(report.page_summary)
    analysis_mode_label = "模型深度检查报告" if report.analysis_mode == "deep" else "静态检测报告"
    parent_report_block = ""
    if report.analysis_mode == "deep":
        parent_links = []
        if report.parent_html_report_path:
            parent_links.append(f"<a href='/{html.escape(report.parent_html_report_path)}' target='_blank'>关联静态 HTML 报告</a>")
        if report.parent_markdown_report_path:
            parent_links.append(f"<a href='/{html.escape(report.parent_markdown_report_path)}' target='_blank'>关联静态 Markdown 报告</a>")
        parent_report_block = f"<p>{' | '.join(parent_links) if parent_links else '未记录关联静态报告。'}</p>"

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>SentinelGuard 哨塔检测报告</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f7fb; color: #172033; }}
header {{ background: linear-gradient(135deg, #111827, #1d4ed8); color: white; padding: 32px 48px; }}
main {{ max-width: 1080px; margin: 24px auto; padding: 0 20px 48px; }}
section {{ background: white; border-radius: 14px; padding: 24px; margin-bottom: 18px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }}
h1, h2 {{ margin-top: 0; }}
.badge {{ display: inline-block; padding: 8px 14px; border-radius: 999px; color: white; background: { _risk_color(report.risk_level) }; font-weight: 700; }}
dl {{ display: grid; grid-template-columns: 140px 1fr; gap: 8px 14px; }}
dt {{ color: #64748b; }}
dd {{ margin: 0; word-break: break-all; }}
.finding {{ border-left: 4px solid #ef4444; padding: 12px 16px; background: #fff7f7; border-radius: 8px; margin: 12px 0; }}
.finding.low {{ border-color: #22c55e; background: #f0fdf4; }}
.finding.medium {{ border-color: #f59e0b; background: #fffbeb; }}
.finding.high, .finding.critical {{ border-color: #dc2626; background: #fef2f2; }}
code {{ background: #e2e8f0; padding: 2px 5px; border-radius: 4px; }}
li {{ margin: 8px 0; }}
table {{ border-collapse: collapse; width: 100%; }}
td {{ border-bottom: 1px solid #e2e8f0; padding: 8px; vertical-align: top; word-break: break-all; }}
</style>
</head>
<body>
<header>
  <h1>SentinelGuard 哨塔检测报告</h1>
  <p>面向网址、小程序与应用软件的协同恶意检测平台</p>
</header>
<main>
  <section>
    <h2>检测结论</h2>
    <p><span class="badge">{html.escape(report.risk_level.upper())}</span></p>
    <p>风险分数：<strong>{report.score}/100</strong></p>
    <p>报告类型：<strong>{html.escape(analysis_mode_label)}</strong></p>
    <p>原始输入：<code>{html.escape(ir.original_input)}</code></p>
    {parent_report_block}
  </section>
  <section>
    <h2>统一 IR 摘要</h2>
    <p>对象类型：{html.escape(ir.target_type)}；状态：{html.escape(ir.status)}</p>
    {url_block}
  </section>
  <section>
    <h2>跳转链与页面线索</h2>
    <ol>{redirect_chain}</ol>
    {page_summary}
  </section>
  <section>
    <h2>风险证据</h2>
    {findings}
  </section>
  <section>
    <h2>{'模型深度研判' if report.analysis_mode == 'deep' else '协同研判'}</h2>
    <ul>{experts}</ul>
  </section>
  <section>
    <h2>扩展能力占位</h2>
    <ul>{placeholders}</ul>
  </section>
</main>
</body>
</html>
"""


def render_markdown_report(report: DetectionReport) -> str:
    ir = report.target_ir
    analysis_mode_label = "模型深度检查报告" if report.analysis_mode == "deep" else "静态检测报告"
    lines = [
        "# SentinelGuard 哨塔检测报告",
        "",
        f"- 风险等级：{report.risk_level}",
        f"- 风险分数：{report.score}/100",
        f"- 报告类型：{analysis_mode_label}",
        f"- 原始输入：{ir.original_input}",
        f"- 对象类型：{ir.target_type}",
        f"- 状态：{ir.status}",
    ]

    if report.parent_html_report_path:
        lines.append(f"- 关联静态 HTML 报告：{report.parent_html_report_path}")
    if report.parent_markdown_report_path:
        lines.append(f"- 关联静态 Markdown 报告：{report.parent_markdown_report_path}")

    lines.extend(["", "## 统一 IR 摘要"])

    if ir.url:
        lines.extend([
            f"- 规范化 URL：{ir.url.normalized_url}",
            f"- 协议：{ir.url.scheme}",
            f"- 主机：{ir.url.hostname}",
            f"- 路径：{ir.url.path}",
            f"- 参数数量：{len(ir.url.query_params)}",
        ])
    else:
        lines.append(ir.message or "该对象类型尚未实现。")

    lines.extend(["", "## 跳转链"])
    lines.extend([f"- {item}" for item in report.redirect_chain] or ["- 未获取跳转链。"])

    lines.extend(["", "## 页面线索"])
    lines.extend(_markdown_dict(report.page_summary))

    lines.extend(["", "## 风险证据"])
    if report.findings:
        for finding in report.findings:
            lines.extend([
                f"### {finding.title}",
                f"- 规则：{finding.rule_id}",
                f"- 严重级别：{finding.severity}",
                f"- 说明：{finding.description}",
                f"- 证据：{finding.evidence}",
                f"- 建议：{finding.recommendation}",
                "",
            ])
    else:
        lines.append("未发现明显风险项。")

    lines.extend(["", "## 模型深度研判" if report.analysis_mode == "deep" else "## 协同研判"])
    lines.extend([f"- **{role}**：{opinion}" for role, opinion in report.expert_opinions.items()])

    lines.extend(["", "## 扩展能力占位"])
    lines.extend([f"- **{key}**：{value}" for key, value in report.placeholders.items()])
    lines.append("")
    return "\n".join(lines)


def _finding_card(finding: DetectionFinding) -> str:
    return f"""
    <div class="finding {html.escape(finding.severity)}">
      <h3>{html.escape(finding.title)} <small>({html.escape(finding.severity)})</small></h3>
      <p>{html.escape(finding.description)}</p>
      <p><strong>证据：</strong><code>{html.escape(finding.evidence)}</code></p>
      <p><strong>建议：</strong>{html.escape(finding.recommendation)}</p>
    </div>
    """


def _dict_table(data: dict) -> str:
    if not data:
        return "<p>未获取页面内容线索。</p>"
    rows = "".join(
        f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(_format_value(value))}</td></tr>"
        for key, value in data.items()
    )
    return f"<table>{rows}</table>"


def _markdown_dict(data: dict) -> Iterable[str]:
    if not data:
        return ["- 未获取页面内容线索。"]
    return [f"- {key}：{_format_value(value)}" for key, value in data.items()]


def _format_value(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "无"
    return str(value)


def _risk_color(risk_level: str) -> str:
    return {
        "critical": "#991b1b",
        "high": "#dc2626",
        "medium": "#f59e0b",
        "low": "#16a34a",
        "invalid": "#64748b",
        "not_implemented": "#64748b",
    }.get(risk_level, "#64748b")
