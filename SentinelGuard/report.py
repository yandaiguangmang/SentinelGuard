from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

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
    apk = ir.apk
    stats = _build_report_stats(report)
    evidence_tags = _build_evidence_tags(report.findings)
    summary_cards = _render_summary_cards(report, stats)
    result_panel = _render_result_panel(report)
    artifact_panel = _render_artifact_panel(ir, url, apk)
    chain_panel = _render_chain_panel(report)
    findings_panel = _render_findings_panel(report)
    discussion_panel = _render_discussion_panel(report)
    model_panel = _render_model_panel(report)
    placeholders_panel = _render_placeholders_panel(report)
    analysis_mode_label = _analysis_mode_label(report)
    parent_report_block = _render_parent_report_block(report)
    browser_evidence_block = _render_browser_evidence_block(report)
    apk_dynamic_block = _render_apk_dynamic_block(report)

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelGuard 哨塔检测报告</title>
<style>
:root {{
  --bg: #0b1220;
  --bg-soft: #0f172a;
  --panel: rgba(15, 23, 42, .72);
  --panel-light: #ffffff;
  --text: #e5eefb;
  --text-muted: #94a3b8;
  --accent: #60a5fa;
  --accent-2: #22c55e;
  --warn: #f59e0b;
  --danger: #ef4444;
  --line: rgba(148, 163, 184, .2);
  --shadow: 0 16px 50px rgba(2, 6, 23, .28);
}}

* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
  background: radial-gradient(circle at top, #16213e 0, #0b1220 38%, #060912 100%);
  color: var(--text);
}}
a {{ color: #bfdbfe; }}
code {{ background: rgba(148, 163, 184, .18); padding: 2px 6px; border-radius: 6px; word-break: break-all; }}
header {{
  position: sticky; top: 0; z-index: 20;
  backdrop-filter: blur(18px);
  background: linear-gradient(135deg, rgba(15, 23, 42, .92), rgba(30, 64, 175, .82));
  border-bottom: 1px solid rgba(255,255,255,.08);
  box-shadow: 0 10px 30px rgba(2, 6, 23, .28);
}}
.hero {{ max-width: 1240px; margin: 0 auto; padding: 22px 22px 18px; }}
.hero h1 {{ margin: 0 0 8px; font-size: clamp(26px, 4vw, 38px); }}
.hero p {{ margin: 4px 0; color: #dbeafe; }}
.nav {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 14px; font-size: 14px; }}
.nav a {{
  text-decoration: none; color: #dbeafe;
  border: 1px solid rgba(219, 234, 254, .18);
  padding: 7px 12px; border-radius: 999px;
  background: rgba(15, 23, 42, .28);
}}
.nav a:hover {{ background: rgba(96, 165, 250, .18); }}
.container {{ max-width: 1240px; margin: 22px auto 72px; padding: 0 18px 24px; }}
.grid {{ display: grid; gap: 18px; }}
.summary-grid {{ grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
.two-col {{ grid-template-columns: minmax(0, 1.7fr) minmax(320px, .95fr); align-items: start; }}
.panel {{
  background: linear-gradient(180deg, rgba(15, 23, 42, .76), rgba(15, 23, 42, .54));
  border: 1px solid rgba(148, 163, 184, .18);
  border-radius: 22px;
  box-shadow: var(--shadow);
  overflow: hidden;
}}
.panel-inner {{ padding: 22px; }}
.section-title {{
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  margin: 0 0 16px; font-size: 20px;
}}
.section-title small {{ color: var(--text-muted); font-weight: 500; }}
.badge {{
  display: inline-flex; align-items: center; gap: 8px;
  padding: 10px 14px; border-radius: 999px; color: white;
  font-size: 14px; font-weight: 800; letter-spacing: .04em;
  background: {_risk_color(report.risk_level)};
  box-shadow: 0 12px 24px rgba(0,0,0,.18);
}}
.metric {{ padding: 18px 18px 20px; background: rgba(255,255,255,.04); border-radius: 18px; border: 1px solid rgba(148, 163, 184, .16); }}
.metric .label {{ color: var(--text-muted); font-size: 13px; margin-bottom: 10px; }}
.metric .value {{ font-size: 30px; font-weight: 800; line-height: 1.1; }}
.metric .hint {{ margin-top: 8px; color: #cbd5e1; font-size: 13px; line-height: 1.6; }}
.metric.risk {{ border-color: rgba(239, 68, 68, .26); }}
.metric.score {{ border-color: rgba(34, 197, 94, .24); }}
.metric.mode {{ border-color: rgba(96, 165, 250, .22); }}
.metric.target {{ border-color: rgba(245, 158, 11, .22); }}
.pill-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }}
.pill {{
  display: inline-flex; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700;
  background: rgba(96,165,250,.16); color: #dbeafe; border: 1px solid rgba(96,165,250,.22);
}}
.pill.muted {{ background: rgba(148,163,184,.12); color: #e2e8f0; border-color: rgba(148,163,184,.2); }}
.pill.high {{ background: rgba(239,68,68,.14); color: #fecaca; border-color: rgba(239,68,68,.22); }}
.pill.medium {{ background: rgba(245,158,11,.16); color: #fde68a; border-color: rgba(245,158,11,.22); }}
.pill.low {{ background: rgba(34,197,94,.14); color: #bbf7d0; border-color: rgba(34,197,94,.22); }}
.panel h3, .panel h4 {{ margin-top: 0; }}
.panel p {{ line-height: 1.75; color: #dbe4f3; }}
.subtle {{ color: var(--text-muted); }}
.scroll-box {{ max-height: 320px; overflow: auto; padding-right: 6px; scroll-behavior: smooth; }}
.scroll-box.slim {{ max-height: 240px; }}
.scroll-box::-webkit-scrollbar {{ width: 10px; height: 10px; }}
.scroll-box::-webkit-scrollbar-thumb {{ background: rgba(148, 163, 184, .42); border-radius: 999px; }}
.scroll-box::-webkit-scrollbar-track {{ background: rgba(15, 23, 42, .16); }}
.grid-list {{ display: grid; gap: 12px; }}
.finding {{
  border-radius: 16px; padding: 14px 16px; margin: 0;
  background: rgba(255,255,255,.04); border: 1px solid rgba(148, 163, 184, .16);
  border-left: 5px solid rgba(148, 163, 184, .48);
}}
.finding.low {{ border-left-color: #22c55e; }}
.finding.medium {{ border-left-color: #f59e0b; }}
.finding.high, .finding.critical {{ border-left-color: #ef4444; }}
.finding h4 {{ margin: 0 0 8px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
.finding .meta {{ color: var(--text-muted); font-size: 13px; }}
.finding p {{ margin: 8px 0 0; }}
.finding .kv {{ display: grid; grid-template-columns: 88px 1fr; gap: 8px 12px; margin-top: 10px; font-size: 14px; }}
.finding .kv b {{ color: #bfdbfe; }}
.expert-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); }}
.expert-card {{
  background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.03));
  border: 1px solid rgba(148, 163, 184, .16); border-radius: 16px; padding: 14px 14px 12px;
  min-height: 160px; overflow: auto; max-height: 250px;
}}
.expert-card h4 {{ margin: 0 0 8px; }}
.expert-card p {{ margin: 0; }}
.timeline {{ display: grid; gap: 12px; }}
.timeline-item {{ position: relative; padding-left: 18px; }}
.timeline-item::before {{
  content: ''; position: absolute; left: 4px; top: 10px; bottom: -10px; width: 2px; background: rgba(148,163,184,.35);
}}
.timeline-item:last-child::before {{ display: none; }}
.timeline-dot {{
  position: absolute; left: 0; top: 7px; width: 10px; height: 10px; border-radius: 50%;
  background: {_risk_color(report.risk_level)}; box-shadow: 0 0 0 4px rgba(255,255,255,.06);
}}
.timeline-item h4 {{ margin: 0 0 6px; }}
.timeline-item p {{ margin: 0; color: #dbe4f3; }}
.table {{ width: 100%; border-collapse: collapse; }}
.table td, .table th {{ border-bottom: 1px solid rgba(148, 163, 184, .16); padding: 10px 8px; vertical-align: top; text-align: left; }}
.table th {{ color: #bfdbfe; width: 180px; }}
.footer-note {{ color: var(--text-muted); font-size: 13px; line-height: 1.7; }}
.section-anchor {{ scroll-margin-top: 110px; }}
.hero-mini {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
.chip {{ padding: 6px 10px; border-radius: 999px; background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.12); color: #e2e8f0; font-size: 12px; }}
.chip.warning {{ background: rgba(245, 158, 11, .12); }}
.chip.success {{ background: rgba(34, 197, 94, .12); }}
.chip.danger {{ background: rgba(239, 68, 68, .12); }}
@media (max-width: 980px) {{
  .two-col {{ grid-template-columns: 1fr; }}
  header {{ position: static; }}
}}
</style>
</head>
<body>
<header>
  <div class="hero">
    <h1>SentinelGuard 哨塔检测报告</h1>
    <p>网页恶意分析 · 静态检测 + 论坛式协同研判 · 滑动查看证据链</p>
    <div class="nav">
      <a href="#result">总览</a>
      <a href="#ir">统一 IR</a>
      <a href="#chain">跳转链</a>
      <a href="#evidence">风险证据</a>
      <a href="#screenshots">页面截图</a>
      <a href="#discussion">协同研判</a>
      <a href="#appendix">扩展信息</a>
    </div>
    <div class="hero-mini">
      <span class="chip warning">{'深度研判' if report.analysis_mode == 'deep' else '静态研判'}</span>
      <span class="chip">证据数 {len(report.findings)}</span>
      <span class="chip {'danger' if report.risk_level in {'high', 'critical'} else 'warning' if report.risk_level == 'medium' else 'success'}">风险 {html.escape(report.risk_level.upper())}</span>
    </div>
  </div>
</header>

<main class="container">
  <div class="grid summary-grid">
    {summary_cards}
  </div>

  <div class="grid two-col" style="margin-top: 18px;">
    <section class="panel section-anchor" id="result">
      <div class="panel-inner">
        <div class="section-title">
          <h3>检测总览</h3>
          <small>{html.escape(analysis_mode_label)}</small>
        </div>
        {result_panel}
        {parent_report_block}
        {browser_evidence_block}
        {apk_dynamic_block}
      </div>
    </section>

    <section class="panel section-anchor" id="ir">
      <div class="panel-inner">
        <div class="section-title">
          <h3>统一 IR 摘要</h3>
          <small>输入归一化与对象识别</small>
        </div>
        {artifact_panel}
      </div>
    </section>
  </div>

  <section class="panel section-anchor" id="chain" style="margin-top: 18px;">
    <div class="panel-inner">
      <div class="section-title">
        <h3>跳转链与页面线索</h3>
        <small>支持滑动查看完整页面摘要</small>
      </div>
      {chain_panel}
    </div>
  </section>

  <section class="panel section-anchor" id="evidence" style="margin-top: 18px;">
    <div class="panel-inner">
      <div class="section-title">
        <h3>风险证据</h3>
        <small>按严重度与规则优先级呈现</small>
      </div>
      {findings_panel}
    </div>
  </section>

  <section class="panel section-anchor" id="screenshots" style="margin-top: 18px;">
    <div class="panel-inner">
      <div class="section-title">
        <h3>页面截图证据</h3>
        <small>仅在高风险 URL 上自动采集</small>
      </div>
      {_render_screenshot_block(report)}
    </div>
  </section>

  <section class="panel section-anchor" id="discussion" style="margin-top: 18px;">
    <div class="panel-inner">
      <div class="section-title">
        <h3>{'模型深度研判' if report.analysis_mode == 'deep' else 'APK 动态协同研判' if report.analysis_mode == 'dynamic' else '协同研判'}</h3>
        <small>主持人 / 静态 / 行为 / 情报 / 处置 / 模型映射</small>
      </div>
      {discussion_panel}
      {model_panel}
    </div>
  </section>

  <section class="panel section-anchor" id="appendix" style="margin-top: 18px;">
    <div class="panel-inner">
      <div class="section-title">
        <h3>扩展信息</h3>
        <small>便于后续扩展更多对象类型</small>
      </div>
      {placeholders_panel}
    </div>
  </section>
</main>
</body>
</html>
"""


def render_markdown_report(report: DetectionReport) -> str:
    ir = report.target_ir
    analysis_mode_label = _analysis_mode_label(report)
    stats = _build_report_stats(report)
    lines = [
        "# SentinelGuard 哨塔检测报告",
        "",
        f"> {analysis_mode_label} · 风险等级：**{report.risk_level.upper()}** · 风险分数：**{report.score}/100**",
        "模型深度研判" if report.analysis_mode == "deep" else "",
        "",
        "## 一、检测结论",
        f"- 原始输入：`{ir.original_input}`",
        f"- 对象类型：`{ir.target_type}`",
        f"- 状态：`{ir.status}`",
        f"- 证据条数：{stats['finding_count']} 条",
        f"- 高危证据：{stats['high_count']} 条",
    ]

    if report.parent_html_report_path or report.parent_markdown_report_path:
        lines.extend(["- 关联静态报告："])
        if report.parent_html_report_path:
            lines.append(f"  - HTML：{report.parent_html_report_path}")
        if report.parent_markdown_report_path:
            lines.append(f"  - Markdown：{report.parent_markdown_report_path}")

    lines.extend(["", "## 二、统一 IR 摘要"])
    if ir.url:
        lines.extend([
            f"- 规范化 URL：`{ir.url.normalized_url}`",
            f"- 协议：`{ir.url.scheme}`",
            f"- 主机：`{ir.url.hostname}`",
            f"- 路径：`{ir.url.path}`",
            f"- 查询参数数量：`{len(ir.url.query_params)}`",
        ])
    else:
        lines.append(ir.message or "该对象类型尚未实现。")

    lines.extend(["", "## 三、跳转链"])
    lines.extend([f"- {item}" for item in report.redirect_chain] or ["- 未获取跳转链。"])

    lines.extend(["", "## 四、页面线索"])
    lines.extend(_markdown_dict(report.page_summary))

    lines.extend(["", "## 四点一、APK 动态沙箱摘要"])
    if report.analysis_mode == "dynamic":
        lines.extend(_markdown_dict(report.apk_dynamic_summary))
        if report.apk_dynamic_artifacts:
            lines.extend([f"- {key}：`{value}`" for key, value in report.apk_dynamic_artifacts.items()])
    else:
        lines.extend(_markdown_browser_evidence(report))

    lines.extend(["", "## 五、截图证据"])
    lines.extend(_markdown_screenshots(report))

    lines.extend(["", "## 六、风险证据"])
    if report.findings:
        for index, finding in enumerate(report.findings, start=1):
            lines.extend([
                f"### {index}. {finding.title}",
                f"- 规则：`{finding.rule_id}`",
                f"- 严重级别：`{finding.severity}`",
                f"- 说明：{finding.description}",
                f"- 证据：`{finding.evidence}`",
                f"- 建议：{finding.recommendation}",
                "",
            ])
    else:
        lines.append("- 未发现明显风险项。")

    lines.extend(["", "## 七、论坛式协同研判"])
    for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
        opinion = report.expert_opinions.get(role, "")
        if opinion:
            model_name = report.expert_models.get(role, "unknown")
            lines.extend([f"### {role}（模型：`{model_name}`）", opinion, ""])

    if report.deep_summary:
        lines.extend(["", "### 主持人最终总结", report.deep_summary, ""])

    if report.expert_models:
        lines.extend(["", "### 专家模型映射"])
        for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
            model_name = report.expert_models.get(role, "unknown")
            lines.append(f"- {role}：`{model_name}`")

    lines.extend(["", "## 八、扩展信息"])
    if report.placeholders:
        lines.extend([f"- **{key}**：{value}" for key, value in report.placeholders.items()])
    else:
        lines.append("- 当前无扩展项。")

    lines.append("")
    return "\n".join(lines)


def _finding_card(finding: DetectionFinding) -> str:
    return f"""
    <div class="finding {html.escape(finding.severity)}">
      <h4>{html.escape(finding.title)} <span class="pill {html.escape(finding.severity)}">{html.escape(finding.severity.upper())}</span></h4>
      <div class="meta">规则：{html.escape(finding.rule_id)}</div>
      <p>{html.escape(finding.description)}</p>
      <div class="kv">
        <b>证据</b><span><code>{html.escape(finding.evidence)}</code></span>
        <b>建议</b><span>{html.escape(finding.recommendation)}</span>
      </div>
    </div>
    """


def _dict_table(data: dict) -> str:
    if not data:
        return "<p class='subtle'>未获取页面内容线索。</p>"
    rows = "".join(
        f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(_format_value(value))}</td></tr>"
        for key, value in data.items()
    )
    return f"<table class='table'>{rows}</table>"


def _markdown_dict(data: dict) -> Iterable[str]:
    if not data:
        return ["- 未获取页面内容线索。"]
    return [f"- {key}：{_format_value(value)}" for key, value in data.items()]


def _format_value(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "无"
    return str(value)


def _analysis_mode_label(report: DetectionReport) -> str:
    if report.analysis_mode == "deep":
        return "模型深度检查报告"
    if report.analysis_mode == "dynamic":
        return "APK 动态沙箱报告"
    return "静态检测报告"


def _build_report_stats(report: DetectionReport) -> dict[str, int]:
    severity_counts = Counter(finding.severity for finding in report.findings)
    return {
        "finding_count": len(report.findings),
        "high_count": severity_counts.get("high", 0) + severity_counts.get("critical", 0),
        "medium_count": severity_counts.get("medium", 0),
        "low_count": severity_counts.get("low", 0),
    }


def _build_evidence_tags(findings: Sequence[DetectionFinding]) -> list[str]:
    if not findings:
        return ["暂无高危证据"]
    tags = []
    for finding in findings[:8]:
        tags.append(f"{finding.severity.upper()} · {finding.title}")
    return tags


def _render_summary_cards(report: DetectionReport, stats: dict[str, int]) -> str:
    cards = [
        _summary_card("风险等级", report.risk_level.upper(), f"{stats['high_count']} 条高危 / {stats['medium_count']} 条中危证据", "risk"),
        _summary_card("风险分数", f"{report.score}/100", "越高表示越值得拦截与复核", "score"),
        _summary_card("分析模式", _analysis_mode_label(report), "静态检测结果可继续叠加深度研判", "mode"),
        _summary_card("输入对象", report.target_ir.target_type, report.target_ir.original_input, "target"),
    ]
    return "".join(cards)


def _summary_card(label: str, value: str, hint: str, variant: str) -> str:
    return f"""
    <article class="panel metric {html.escape(variant)}">
      <div class="label">{html.escape(label)}</div>
      <div class="value">{html.escape(value)}</div>
      <div class="hint">{html.escape(hint)}</div>
    </article>
    """


def _render_result_panel(report: DetectionReport) -> str:
    tags = _build_evidence_tags(report.findings)
    tag_html = "".join(
        f"<span class='pill {'high' if tag.startswith(('CRITICAL', 'HIGH')) else 'medium' if tag.startswith('MEDIUM') else 'low'}'>{html.escape(tag)}</span>"
        for tag in tags
    )
    return f"""
      <p><span class="badge">{html.escape(report.risk_level.upper())}</span></p>
      <p>风险分数：<strong>{report.score}/100</strong></p>
      <p>原始输入：<code>{html.escape(report.target_ir.original_input)}</code></p>
      <p>报告类型：<strong>{html.escape(_analysis_mode_label(report))}</strong></p>
      <div class="pill-row">{tag_html}</div>
    """


def _render_url_panel(ir, url) -> str:
    if not url:
        return "<p class='subtle'>该对象不是网址，已切换到 APK / 其他对象摘要。</p>"
    rows = [
        ("规范化 URL", url.normalized_url),
        ("协议", url.scheme),
        ("主机", url.hostname),
        ("端口", str(url.port or "-")),
        ("路径", url.path),
        ("查询串", url.query or "-"),
        ("片段", url.fragment or "-"),
        ("参数数量", str(len(url.query_params))),
        ("用户名", url.username or "-"),
        ("携带密码", "是" if url.has_password else "否"),
        ("是否 IP", "是" if url.is_ip_address else "否"),
    ]
    items = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in rows)
    return f"<table class='table'>{items}</table>"


def _render_artifact_panel(ir, url, apk) -> str:
    if url:
        return _render_url_panel(ir, url)
    if apk:
        rows = [
            ("APK 文件", apk.file_name),
            ("规范化路径", apk.normalized_path),
            ("包名", apk.package_name or "-"),
            ("版本名", apk.version_name or "-"),
            ("版本号", apk.version_code or "-"),
            ("SHA256", apk.sha256 or "-"),
            ("大小", f"{apk.size_bytes} 字节"),
            ("权限数量", str(len(apk.permissions))),
            ("组件数量", str(len(apk.activities) + len(apk.services) + len(apk.receivers) + len(apk.providers))),
            ("证书主体", apk.certificate_subject or "-"),
            ("证书签发者", apk.certificate_issuer or "-"),
            ("证书指纹", apk.certificate_sha256 or "-"),
        ]
        items = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in rows)
        return f"<table class='table'>{items}</table>"
    return f"<p>{html.escape(ir.message or '当前对象尚未实现专用摘要。')}</p>"


def _render_chain_panel(report: DetectionReport) -> str:
    redirect_chain = "".join(f"<li>{html.escape(item)}</li>" for item in report.redirect_chain) or "<li>未获取跳转链。</li>"
    page_summary = _dict_table(report.page_summary)
    tags = _build_evidence_tags(report.findings)
    tag_html = "".join(f"<span class='pill muted'>{html.escape(tag)}</span>" for tag in tags)
    return f"""
      <div class="scroll-box">
        <h4>跳转链</h4>
        <ol>{redirect_chain}</ol>
        <h4>页面线索</h4>
        {page_summary}
      </div>
      <div class="pill-row">{tag_html}</div>
    """


def _render_findings_panel(report: DetectionReport) -> str:
    if not report.findings:
        return "<p>未发现明显风险项。</p>"
    grouped = _group_findings_by_severity(report.findings)
    blocks = []
    for severity in ("critical", "high", "medium", "low"):
        items = grouped.get(severity, [])
        if not items:
            continue
        cards = "".join(_finding_card(finding) for finding in items)
        blocks.append(f"<h4>{severity.upper()}（{len(items)}）</h4><div class='grid-list'>{cards}</div>")
    return f"<div class='scroll-box slim'>{''.join(blocks)}</div>"


def _render_discussion_panel(report: DetectionReport) -> str:
    expert_cards = ""
    for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
        opinion = report.expert_opinions.get(role, "")
        model_name = report.expert_models.get(role, "unknown")
        expert_cards += f"""
        <article class="expert-card">
          <h4>{html.escape(role)} <span class="pill muted">{html.escape(model_name)}</span></h4>
          <p>{html.escape(opinion or '无')}</p>
        </article>
        """

    timeline = _build_discussion_timeline(report)
    return f"""
      <div class="expert-grid">{expert_cards}</div>
      <div style="height: 14px"></div>
      <div class="grid two-col">
        <div class="panel" style="box-shadow:none; background: rgba(255,255,255,.02);">
          <div class="panel-inner">
            <h4 style="margin-top:0;">研判时间线</h4>
            <div class="timeline">{timeline}</div>
          </div>
        </div>
        <div class="panel" style="box-shadow:none; background: rgba(255,255,255,.02);">
          <div class="panel-inner">
            <h4 style="margin-top:0;">处置要点</h4>
            <ul>
              <li>优先核验最终域名、证书与跳转落点。</li>
              <li>不要在高危或中危页面输入账号、验证码和支付信息。</li>
              <li>对下载型落点优先在隔离环境或沙箱中复核。</li>
              <li>静态规则与深度研判的结论应结合人工确认。</li>
            </ul>
          </div>
        </div>
      </div>
    """


def _render_model_panel(report: DetectionReport) -> str:
    if report.analysis_mode not in {"deep", "dynamic"} or not report.expert_models:
        return ""

    rows = []
    for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
        rows.append(
            f"<tr><th>{html.escape(role)}</th><td>{html.escape(report.expert_models.get(role, 'unknown'))}</td><td>{html.escape(report.expert_opinions.get(role, ''))}</td></tr>"
        )
    table = "".join(rows)
    summary = html.escape(report.deep_summary or "主持人已汇总各专家意见并形成最终结论。")
    return f"""
      <div style="height: 14px"></div>
      <div class="panel" style="box-shadow:none; background: rgba(255,255,255,.02);">
        <div class="panel-inner">
          <h4 style="margin-top:0;">专家模型映射与主持人总结</h4>
          <p class="subtle">{summary}</p>
          <div class="scroll-box slim">
            <table class='table'>
              <thead><tr><th>角色</th><th>模型</th><th>核心意见</th></tr></thead>
              <tbody>{table}</tbody>
            </table>
          </div>
        </div>
      </div>
    """


def _render_placeholders_panel(report: DetectionReport) -> str:
    if not report.placeholders:
        return "<p class='footer-note'>当前暂无扩展能力占位。</p>"
    items = "".join(
        f"<li><strong>{html.escape(key)}</strong>：{html.escape(value)}</li>"
        for key, value in report.placeholders.items()
    )
    return f"<ul>{items}</ul><p class='footer-note'>后续可继续扩展证书信誉、域名黑名单与威胁情报联动。</p>"


def _render_parent_report_block(report: DetectionReport) -> str:
    if report.analysis_mode not in {"deep", "dynamic"}:
        return ""
    links = []
    if report.parent_html_report_path:
        links.append(f"<a href='{html.escape(report.parent_html_report_path)}' target='_blank'>关联静态 HTML 报告</a>")
    if report.parent_markdown_report_path:
        links.append(f"<a href='{html.escape(report.parent_markdown_report_path)}' target='_blank'>关联静态 Markdown 报告</a>")
    if not links:
        return "<p class='subtle'>未记录关联静态报告。</p>"
    return f"<p class='subtle'>关联静态报告：{' · '.join(links)}</p>"


def _render_browser_evidence_block(report: DetectionReport) -> str:
    evidence = report.page_summary if isinstance(report.page_summary, dict) else {}
    if not evidence:
        return ""

    proxy_info = ""
    if evidence.get("fetch_mode"):
        proxy_info = f"<p class='subtle'>抓取模式：{html.escape(str(evidence.get('fetch_mode')))} / 代理：{'是' if evidence.get('proxy_used') else '否'}</p>"

    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>页面观察线索</h4>
          {proxy_info}
        </div>
      </div>
    """


def _render_screenshot_block(report: DetectionReport) -> str:
    screenshots = report.screenshots or []
    if not screenshots:
        return "<p class='subtle'>未采集到截图证据。</p>"

    cards = []
    for index, shot in enumerate(screenshots, start=1):
        title = html.escape(str(shot.get("page_title") or shot.get("final_url") or shot.get("url") or f"截图 {index}"))
        url = html.escape(str(shot.get("url") or ""))
        final_url = html.escape(str(shot.get("final_url") or ""))
        size_bytes = html.escape(_format_value(shot.get("size_bytes", 0)))
        viewport = shot.get("viewport") or {}
        viewport_text = html.escape(_format_value(viewport))
        captured_at = html.escape(str(shot.get("captured_at") or ""))
        img_src = html.escape(f"data:{shot.get('mime_type', 'image/png')};base64,{shot.get('base64', '')}")
        cards.append(f"""
        <article class='screenshot-card'>
          <h4>截图 {index} · {title}</h4>
          <div class='subtle'>URL：<code>{url}</code></div>
          <div class='subtle'>最终地址：<code>{final_url}</code></div>
          <div class='subtle'>大小：{size_bytes} 字节 · 视口：{viewport_text} · 采集时间：{captured_at}</div>
          <div style='margin-top: 12px; overflow: auto; border-radius: 14px; background: #0f172a; padding: 10px;'>
            <img src="{img_src}" alt="{title}" />
          </div>
        </article>
        """)
    return f"<div class='screenshot-grid'>{''.join(cards)}</div>"


def _markdown_screenshots(report: DetectionReport) -> list[str]:
    screenshots = report.screenshots or []
    if not screenshots:
        return ["- 未采集到截图证据。"]

    lines = [f"- 截图数量：`{len(screenshots)}` 张，完整图像请查看 HTML 报告。"]
    for index, shot in enumerate(screenshots, start=1):
        lines.extend([
            f"- 截图 {index}：",
            f"  - URL：`{shot.get('url', '')}`",
            f"  - 最终地址：`{shot.get('final_url', '')}`",
            f"  - 大小：`{shot.get('size_bytes', 0)}` 字节",
            f"  - 视口：`{shot.get('viewport', {})}`",
        ])
    return lines


def _render_apk_dynamic_block(report: DetectionReport) -> str:
    if report.analysis_mode != "dynamic" and not report.apk_dynamic_summary and not report.apk_dynamic_artifacts:
        return ""

    summary_rows = []
    if report.apk_dynamic_summary:
        for key, value in report.apk_dynamic_summary.items():
            summary_rows.append(f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(_format_value(value))}</td></tr>")
    if report.apk_dynamic_artifacts:
        for key, value in report.apk_dynamic_artifacts.items():
            summary_rows.append(f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(_format_value(value))}</td></tr>")
    rows = "".join(summary_rows) or "<tr><td>暂无动态摘要。</td></tr>"
    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>APK 动态沙箱摘要</h4>
          <div class='scroll-box slim'>
            <table class='table'>{rows}</table>
          </div>
        </div>
      </div>
    """


def _markdown_browser_evidence(report: DetectionReport) -> list[str]:
    lines: list[str] = []
    evidence = report.page_summary if isinstance(report.page_summary, dict) else {}
    if evidence.get("fetch_mode"):
        lines.append(f"- 抓取模式：`{evidence.get('fetch_mode')}`")
    if evidence.get("proxy_used") is not None:
        lines.append(f"- 代理是否参与：`{bool(evidence.get('proxy_used'))}`")
    return lines


def _group_findings_by_severity(findings: Sequence[DetectionFinding]) -> dict[str, list[DetectionFinding]]:
    grouped: dict[str, list[DetectionFinding]] = {"critical": [], "high": [], "medium": [], "low": []}
    for finding in findings:
        grouped.setdefault(finding.severity, []).append(finding)
    return grouped


def _build_discussion_timeline(report: DetectionReport) -> str:
    items = []
    role_map = {
        "主持人": "汇总各方证据，先定风险基调。",
        "静态分析员": "聚焦域名结构、参数、敏感关键词等静态特征。",
        "行为分析员": "聚焦跳转链、自动跳转、下载与表单行为。",
        "情报分析员": "说明离线/外部情报可用性及局限。",
        "处置建议员": "给出拦截、隔离、复核与留痕建议。",
    }
    for index, role in enumerate(["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"], start=1):
        opinion = report.expert_opinions.get(role, "")
        if not opinion:
            continue
        items.append(
            f"""
            <div class="timeline-item">
              <span class="timeline-dot"></span>
              <h4>{index}. {html.escape(role)}</h4>
              <p>{html.escape(role_map.get(role, ''))}</p>
              <p class="subtle" style="margin-top:6px;">{html.escape(opinion)}</p>
            </div>
            """
        )
    return "".join(items) or "<p>暂无协同研判内容。</p>"


def _risk_color(risk_level: str) -> str:
    return {
        "critical": "#991b1b",
        "high": "#dc2626",
        "medium": "#f59e0b",
        "low": "#16a34a",
        "invalid": "#64748b",
        "not_implemented": "#64748b",
    }.get(risk_level, "#64748b")
