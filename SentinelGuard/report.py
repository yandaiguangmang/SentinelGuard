from __future__ import annotations

import base64
import mimetypes
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
    artifact_panel = _render_artifact_panel(report, ir, url, apk)
    chain_panel = _render_chain_panel(report)
    findings_panel = _render_findings_panel(report)
    discussion_panel = _render_discussion_panel(report)
    model_panel = _render_model_panel(report)
    placeholders_panel = _render_placeholders_panel(report)
    analysis_mode_label = _analysis_mode_label(report)
    parent_report_block = _render_parent_report_block(report)
    browser_evidence_block = _render_browser_evidence_block(report)
    apk_dynamic_block = _render_apk_dynamic_block(report)
    apk_graph_block = _render_apk_graph_block(report)
    apk_consistency_block = _render_apk_consistency_block(report)
    apk_robustness_block = _render_apk_robustness_block(report)
    arbitration_block = _render_arbitration_block(report)
    role_limitations_block = _render_role_limitations_block(report)

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
    .scroll-box.wide {{ max-height: 420px; }}
    .scroll-box.slim {{ max-height: 240px; }}
    .scroll-box.tall {{ max-height: 680px; }}
.scroll-box::-webkit-scrollbar {{ width: 10px; height: 10px; }}
.scroll-box::-webkit-scrollbar-thumb {{ background: rgba(148, 163, 184, .42); border-radius: 999px; }}
.scroll-box::-webkit-scrollbar-track {{ background: rgba(15, 23, 42, .16); }}
.hscroll {{ overflow-x: auto; overflow-y: hidden; padding-bottom: 4px; }}
.hscroll .table {{ min-width: 880px; }}
.hscroll td, .hscroll th {{ white-space: nowrap; }}
.text-scroll {{ overflow-x: auto; overflow-y: hidden; white-space: nowrap; }}
.text-scroll code, .text-scroll span {{ white-space: nowrap; }}
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
        {apk_graph_block}
        {apk_consistency_block}
        {apk_robustness_block}
        {arbitration_block}
        {role_limitations_block}
      </div>
    </section>

    <section class="panel section-anchor" id="ir">
      <div class="panel-inner">
        <div class="section-title">
          <h3>统一 IR 摘要</h3>
          <small>{html.escape(analysis_mode_label)} · URL 采用 0.5×证据分数 + 0.5×深度研判分数，APK 采用 0.4×证据分数 + 0.3×深度研判分数 + 仲裁修正 + 鲁棒性奖励</small>
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

  <section class="panel section-anchor" id="discussion" style="margin-top: 18px;">
    <div class="panel-inner">
      <div class="section-title">
        <h3>{'模型深度研判' if report.analysis_mode == 'deep' else 'APK 动态协同研判' if report.analysis_mode == 'dynamic' else '协同研判'}</h3>
        <small>主持人 / 静态 / 行为 / 情报 / 处置 / 模型映射</small>
      </div>
      {discussion_panel}
      {model_panel}
        {role_limitations_block}
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
        f"> 证据分数：**{report.evidence_score}/100** · 深度研判分数：**{report.deep_score if report.deep_score is not None else '-'} /100**",
        f"> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。",
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
    elif ir.apk:
        lines.extend([
            f"- APK 文件：`{ir.apk.file_name}`",
            f"- 包名：`{ir.apk.package_name or '-'}`",
            f"- 版本名：`{ir.apk.version_name or '-'}`",
            f"- 版本号：`{ir.apk.version_code or '-'}`",
            f"- SHA256：`{ir.apk.sha256 or '-'}`",
            f"- 大小：`{ir.apk.size_bytes}` 字节",
            f"- 关键文件数：`{len(ir.apk.key_files)}`",
        ])
        if ir.apk.robustness:
            lines.extend([
                "",
                "### APK 鲁棒性验证",
                f"- 鲁棒性分数：`{ir.apk.robustness.robustness_score}`",
                f"- 检测到的对抗技术：{', '.join(ir.apk.robustness.adversarial_techniques) if ir.apk.robustness.adversarial_techniques else '无'}",
                f"- 防沙箱：`{ir.apk.robustness.anti_emulator_detected}`",
                f"- 混淆：`{ir.apk.robustness.obfuscation_detected}`",
                f"- 反射：`{ir.apk.robustness.reflection_detected}`",
                f"- 动态加载：`{ir.apk.robustness.dynamic_loading_detected}`",
            ])
        if ir.apk.graph_data:
            lines.extend(["", "### APK 图结构分析", "- 已检测到 APK 图结构数据，可在 HTML 报告中查看 CFG / FCG / API 调用图统计。"])
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

    apk_graph_lines = _markdown_apk_graph_block(report)
    if apk_graph_lines:
        lines.extend(["", "## 四点二、图结构分析"])
        lines.extend(apk_graph_lines)

    consistency_lines = _markdown_apk_consistency_block(report)
    if consistency_lines:
        lines.extend(["", "## 四点三、一致性验证"])
        lines.extend(consistency_lines)

    robustness_lines = _markdown_apk_robustness_block(report)
    if robustness_lines:
        lines.extend(["", "## 四点四、鲁棒性分析"])
        lines.extend(robustness_lines)

    lines.extend(["", "## 五、风险证据"])
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

    lines.extend(["", "## 六、论坛式协同研判"])
    for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
        opinion = report.expert_opinions.get(role, "")
        if opinion:
            model_name = report.expert_models.get(role, "unknown")
            lines.extend([f"### {role}（模型：`{model_name}`）", opinion, ""])

    if report.deep_summary:
        lines.extend(["", "### 主持人最终总结", report.deep_summary, ""])

    role_limitations_lines = _markdown_role_limitations(report)
    if role_limitations_lines:
        lines.extend(["", "## 六点一、角色结果说明"])
        lines.extend(role_limitations_lines)

    arbitration_lines = _markdown_arbitration_block(report)
    if arbitration_lines:
        lines.extend(["", "## 七、仲裁结果"])
        lines.extend(arbitration_lines)

    if report.expert_models:
        lines.extend(["", "### 专家模型映射"])
        for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
            model_name = report.expert_models.get(role, "unknown")
            lines.append(f"- {role}：`{model_name}`")

    lines.extend(["", "## 七、扩展信息"])
    if report.placeholders:
        lines.extend([f"- **{key}**：{value}" for key, value in report.placeholders.items()])
    else:
        lines.append("- 当前无扩展项。")

    lines.append("")
    return "\n".join(lines)


def _role_summary_reason(role: str, opinion: str) -> str:
    text = (opinion or "").strip()
    if not text:
        return "该角色未产生有效输出。"

    normalized_text = text.lower()
    if any(keyword in normalized_text for keyword in ["模型暂不可用", "降级", "failed", "failure", "error"]):
        return "该角色模型调用失败，已使用静态分析结果降级替代。"
    if any(keyword in text for keyword in ["本地汇总已完成", "现有角色摘要补齐", "已由静态分析摘要补齐", "已完成的四位专家意见", "本地归纳"]):
        return "已返回补齐后的研判结果。"
    if role == "主持人" and any(keyword in text for keyword in ["已完成", "最终结论", "综合风险等级", "综合研判结论"]):
        return "已返回补齐后的研判结果。"
    if role == "静态分析员" and "动态沙箱" in text and ("未执行" in text or "未接入" in text):
        return "该角色当前仅输出静态研判结果，原因是 APK 动态沙箱尚未执行或未接入。"
    if "未接入外部威胁情报" in text:
        return "该角色当前仅能基于本地离线信息输出结论，原因是外部威胁情报未接入。"
    if "模型暂不可用" in text or "降级" in text:
        return "该角色模型调用失败，已使用静态分析结果降级替代。"
    return "已返回独立研判结果。"


def _markdown_role_limitations(report: DetectionReport) -> list[str]:
    if report.target_ir.target_type != "apk":
        return []
    lines = []
    for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
        opinion = report.expert_opinions.get(role, "")
        reason = _role_summary_reason(role, opinion)
        if reason == "已返回独立研判结果。":
            continue
        lines.append(f"- **{role}**：{reason}")
    return lines


def _render_role_limitations_block(report: DetectionReport) -> str:
    if report.target_ir.target_type != "apk":
        return ""
    items = []
    for role in ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]:
        opinion = report.expert_opinions.get(role, "")
        reason = _role_summary_reason(role, opinion)
        if reason == "已返回独立研判结果。":
            continue
        items.append(
            f"<li><strong>{html.escape(role)}</strong>：{html.escape(reason)}</li>"
        )
    if not items:
        return ""
    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>角色结果说明</h4>
          <p class='subtle'>如果某些角色只给出了静态结果，以下会说明原因；这通常发生在动态沙箱未开启、模型服务不可用或外部情报未接入时。</p>
          <ul>{''.join(items)}</ul>
        </div>
      </div>
    """


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
        _summary_card("证据分数", f"{report.evidence_score}/100", "基于已采集证据统一计算", "score"),
        _summary_card("深度研判分数", f"{report.deep_score if report.deep_score is not None else '-'} /100", "主持人总结后的单独评分", "mode"),
        _summary_card("最终风险分数", f"{report.score}/100", "APK：0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励", "target"),
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
    deep_score_text = str(report.deep_score) if report.deep_score is not None else "-"
    return f"""
      <p><span class="badge">{html.escape(report.risk_level.upper())}</span></p>
      <p>证据分数：<strong>{report.evidence_score}/100</strong></p>
      <p>深度研判分数：<strong>{html.escape(deep_score_text)}/100</strong></p>
      <p>最终风险分数：<strong>{report.score}/100</strong></p>
      <p class="subtle">APK 组合公式：<code>0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励</code></p>
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


def _render_artifact_panel(report: DetectionReport, ir, url, apk) -> str:
    if url:
        return f"<div class='hscroll'>{_render_url_panel(ir, url)}</div>"
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
        if apk.robustness:
            rows.extend([
                ("鲁棒性分数", str(apk.robustness.robustness_score)),
                ("对抗技术", ", ".join(apk.robustness.adversarial_techniques) or "-"),
                ("防沙箱", str(apk.robustness.anti_emulator_detected)),
                ("混淆", str(apk.robustness.obfuscation_detected)),
                ("反射", str(apk.robustness.reflection_detected)),
                ("动态加载", str(apk.robustness.dynamic_loading_detected)),
            ])
        items = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in rows)
        artifact_html = f"<table class='table'>{items}</table>"
        return f"<div class='hscroll'>{artifact_html}</div>"
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
        <div style='height:12px'></div>
        {_render_apk_ui_trace_block(report, compact=True)}
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
    return f"<div class=\"scroll-box tall\">{''.join(blocks)}</div>"


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
    proxy_info = ""
    if evidence.get("fetch_mode"):
        proxy_info = f"<p class='subtle'>抓取模式：{html.escape(str(evidence.get('fetch_mode')))} / 代理：{'是' if evidence.get('proxy_used') else '否'}</p>"

    summary_html = _render_page_summary(report) if evidence else "<p class='subtle'>未获取页面内容线索。</p>"

    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>页面观察线索</h4>
          {proxy_info}
          {summary_html}
        </div>
      </div>
    """


def _render_page_summary(report: DetectionReport) -> str:
    evidence = report.page_summary if isinstance(report.page_summary, dict) else {}
    return _dict_table(evidence)


def _render_apk_ui_trace_block(report: DetectionReport, compact: bool = False) -> str:
    trace_paths = []
    artifacts = getattr(report, "apk_dynamic_artifacts", None)
    if isinstance(artifacts, dict):
        trace_paths.extend([str(item) for item in artifacts.get("ui_trace_paths", []) or [] if str(item).strip()])
        trace_dir = str(artifacts.get("ui_trace_dir") or "").strip()
        if trace_dir:
            trace_dir_path = Path(trace_dir)
            if trace_dir_path.exists():
                trace_paths.extend(str(path.as_posix()) for path in sorted(trace_dir_path.glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True))

    if not trace_paths:
        trace_paths.extend(_find_latest_apk_screenshots())

    if not trace_paths:
        return "<p class='subtle'>未获取到动态截图。</p>"

    image_blocks = []
    seen = set()
    for raw_path in trace_paths:
        if raw_path in seen:
            continue
        seen.add(raw_path)
        encoded = _encode_image_data_uri(Path(raw_path))
        if not encoded:
            continue
        image_blocks.append(f"""
          <figure style='margin:14px 0 0;'>
            <img src='{encoded}' alt='APK 动态截图' style='max-width:100%; border-radius:16px; border:1px solid rgba(148,163,184,.18); display:block;'>
            <figcaption class='subtle' style='margin-top:8px; word-break:break-all;'>{html.escape(raw_path)}</figcaption>
          </figure>
        """)
        if len(image_blocks) >= 4:
            break

    if not image_blocks:
        return "<p class='subtle'>截图文件存在，但无法读取为图片。</p>"

    content = f"""
      <h4 style='margin-top:0;'>APK 动态截图</h4>
      <p class='subtle'>自动展示当次分析生成的 UI 轨迹截图，优先读取 information 目录下最近的 PNG 产物。</p>
      <div class='grid-list'>{''.join(image_blocks)}</div>
    """
    if compact:
        return f"<div class='grid-list'>{''.join(image_blocks)}</div>"
    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          {content}
        </div>
      </div>
    """


def _find_latest_apk_screenshots(limit: int = 4) -> list[str]:
    project_root = Path(__file__).resolve().parents[1]
    info_dir = project_root / "information"
    if not info_dir.exists():
        return []

    candidates: list[Path] = []
    for path in info_dir.rglob("*.png"):
        try:
            if path.is_file():
                candidates.append(path)
        except OSError:
            continue
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [str(path.as_posix()) for path in candidates[:limit]]


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


def _render_apk_graph_block(report: DetectionReport) -> str:
    apk = report.target_ir.apk
    graph_data = _apk_graph_data_map(getattr(apk, "graph_data", None) if apk else None)
    if not apk:
        return ""

    stats = graph_data.get("stats", {}) if isinstance(graph_data.get("stats", {}), dict) else {}
    cfg = graph_data.get("cfg", {}) if isinstance(graph_data.get("cfg", {}), dict) else {}
    fcg = graph_data.get("fcg", {}) if isinstance(graph_data.get("fcg", {}), dict) else {}
    api_graph = graph_data.get("api_graph", {}) if isinstance(graph_data.get("api_graph", {}), dict) else {}

    cfg_nodes = int(stats.get("cfg_node_count", len(cfg.get("nodes", []) or [])))
    cfg_edges = int(stats.get("cfg_edge_count", len(cfg.get("edges", []) or [])))
    fcg_nodes = int(stats.get("fcg_node_count", len(fcg.get("nodes", []) or [])))
    fcg_edges = int(stats.get("fcg_edge_count", len(fcg.get("edges", []) or [])))
    api_nodes = int(stats.get("api_graph_node_count", len(api_graph.get("nodes", []) or [])))
    api_edges = int(stats.get("api_graph_edge_count", len(api_graph.get("edges", []) or [])))
    api_call_counts = api_graph.get("api_call_counts", {}) if isinstance(api_graph.get("api_call_counts", {}), dict) else {}
    total_api_calls = sum(int(v or 0) for v in api_call_counts.values())
    density = stats.get("density")
    density_text = f"{float(density):.4f}" if density is not None else "-"
    sensitive_api_dist = ", ".join(f"{html.escape(str(k))}:{v}" for k, v in sorted(api_call_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))[:12]) or "无"
    fallback_reason = str(graph_data.get("fallback_reason") or "").strip()
    graph_warnings = list(graph_data.get("warnings", []) or [])
    if isinstance(apk.evidence_summary, dict):
        graph_warnings.extend([str(item) for item in apk.evidence_summary.get("warnings", []) or []])
    warning_text = "；".join([text for text in [fallback_reason, *graph_warnings] if text])
    graph_status = "已生成"
    if graph_data.get("fallback"):
        graph_status = "回退生成"
    elif not graph_data:
        graph_status = "图结构缺失"
        if not warning_text:
            warning_text = "未检测到图结构数据，可能是 APK 解析失败、androguard 不可用或未能提取 DEX 图。"
    elif api_nodes == 0 and api_edges == 0 and not api_call_counts:
        graph_status = "API 图为空"
        if not warning_text:
            warning_text = "已提取 CFG / FCG，但未识别到敏感 API 调用。"

    api_call_items = "".join(
        f"<li><code>{html.escape(str(k))}</code>：{v}</li>"
        for k, v in sorted(api_call_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))[:20]
    ) or "<li>无</li>"

    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>CFG / FCG / API 调用图分析</h4>
          <p class='subtle'>以下统计基于 APK 解析出的 CFG、FCG 与 API 调用图，仅展示关键数字，不绘制图形。</p>
          <p class='subtle'>图结构状态：<strong>{html.escape(graph_status)}</strong>{f" · 原因：{html.escape(warning_text)}" if warning_text else ""}</p>
          <table class='table'>
            <tr><th>CFG 节点数</th><td>{cfg_nodes}</td></tr>
            <tr><th>CFG 边数</th><td>{cfg_edges}</td></tr>
            <tr><th>FCG 节点数</th><td>{fcg_nodes}</td></tr>
            <tr><th>FCG 边数</th><td>{fcg_edges}</td></tr>
            <tr><th>FCG 密度</th><td>{density_text}</td></tr>
            <tr><th>API 调用图节点数</th><td>{api_nodes}</td></tr>
            <tr><th>API 调用图边数</th><td>{api_edges}</td></tr>
            <tr><th>API 总调用数</th><td>{total_api_calls}</td></tr>
            <tr><th>敏感 API 调用分布</th><td>{sensitive_api_dist}</td></tr>
          </table>
          <div style='height:12px'></div>
          <h4>API 调用明细</h4>
          <ul>{api_call_items}</ul>
        </div>
      </div>
    """


def _render_apk_consistency_block(report: DetectionReport) -> str:
    arbitration = _coerce_arbitration_result(report.arbitration_result)
    if not arbitration:
        apk = report.target_ir.apk
        arbitration = _coerce_arbitration_result(getattr(apk, "arbitration_result", None)) if apk else None
    if not arbitration:
        return """
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>一致性验证</h4>
          <p class='subtle'>未获取一致性分析结果。可能原因：当前分析流程未启用仲裁器，或仲裁结果未返回；这不代表没有一致性分析，只是本次报告无法展示该结果。</p>
          <table class='table'>
            <tr><th>一致性分数</th><td>-</td></tr>
            <tr><th>一致性等级</th><td>-</td></tr>
            <tr><th>分歧点</th><td>未获取</td></tr>
            <tr><th>被污染模块</th><td>未获取</td></tr>
          </table>
        </div>
      </div>
        """

    consistency_score = arbitration.get("consistency_score")
    consistency_level = str(arbitration.get("consistency_level", "-") or "-").lower()
    discrepancies = list(arbitration.get("discrepancies", []) or [])
    suspected = list(arbitration.get("suspected_compromised", []) or [])
    level_label, level_color = _consistency_level_style(consistency_level)
    discrepancy_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in discrepancies) or "<li>无</li>"
    suspected_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in suspected) or "<li>无</li>"

    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>一致性验证</h4>
          <p class='subtle'>
            <span class='pill' style='background:{level_color}; border-color:{level_color}; color:#fff;'>一致性 {html.escape(level_label)}</span>
            <span class='pill muted' style='margin-left:8px;'>一致性分数 {html.escape(str(consistency_score if consistency_score is not None else '-'))}</span>
          </p>
          <table class='table'>
            <tr><th>一致性分数</th><td>{html.escape(str(consistency_score if consistency_score is not None else '-'))}</td></tr>
            <tr><th>一致性等级</th><td><span class='pill' style='background:{level_color}; border-color:{level_color}; color:#fff;'>{html.escape(str(consistency_level).upper())}</span></td></tr>
            <tr><th>分歧点</th><td><ul>{discrepancy_items}</ul></td></tr>
            <tr><th>被污染模块</th><td><ul>{suspected_items}</ul></td></tr>
          </table>
        </div>
      </div>
    """


def _render_apk_robustness_block(report: DetectionReport) -> str:
    apk = report.target_ir.apk
    robustness = getattr(apk, "robustness", None) if apk else None
    if not robustness:
        return ""

    techniques = list(getattr(robustness, "adversarial_techniques", []) or [])
    score = getattr(robustness, "robustness_score", None)
    assessment = _robustness_assessment(score, techniques)
    techniques_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in techniques) or "<li>无</li>"

    warning_color = "#dc2626" if techniques else "#f59e0b" if (score is not None and float(score) >= 70) else "#16a34a"
    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>鲁棒性分析</h4>
          <p class='subtle'>
            <span class='pill' style='background:{warning_color}; border-color:{warning_color}; color:#fff;'>抗干扰能力：{html.escape(assessment)}</span>
            <span class='pill muted' style='margin-left:8px;'>鲁棒性分数 {html.escape(str(score if score is not None else '-'))}</span>
          </p>
          <table class='table'>
            <tr><th>对抗技术</th><td><ul>{techniques_html}</ul></td></tr>
            <tr><th>鲁棒性分数</th><td>{html.escape(str(score if score is not None else '-'))}</td></tr>
            <tr><th>抗干扰能力评估</th><td>{html.escape(assessment)}</td></tr>
          </table>
        </div>
      </div>
    """


def _markdown_apk_graph_block(report: DetectionReport) -> list[str]:
    apk = report.target_ir.apk
    graph_data = _apk_graph_data_map(getattr(apk, "graph_data", None) if apk else None)
    if not apk:
        return []
    stats = graph_data.get("stats", {}) if isinstance(graph_data.get("stats", {}), dict) else {}
    cfg = graph_data.get("cfg", {}) if isinstance(graph_data.get("cfg", {}), dict) else {}
    fcg = graph_data.get("fcg", {}) if isinstance(graph_data.get("fcg", {}), dict) else {}
    api_graph = graph_data.get("api_graph", {}) if isinstance(graph_data.get("api_graph", {}), dict) else {}
    api_call_counts = api_graph.get("api_call_counts", {}) if isinstance(api_graph.get("api_call_counts", {}), dict) else {}
    api_nodes = int(stats.get("api_graph_node_count", len(api_graph.get("nodes", []) or [])))
    api_edges = int(stats.get("api_graph_edge_count", len(api_graph.get("edges", []) or [])))
    total_api_calls = sum(int(v or 0) for v in api_call_counts.values())
    density = stats.get("density")
    fallback_reason = str(graph_data.get("fallback_reason") or "").strip()
    graph_warnings = [str(item) for item in (graph_data.get("warnings", []) or []) if str(item).strip()]
    if isinstance(apk.evidence_summary, dict):
        graph_warnings.extend([str(item) for item in apk.evidence_summary.get("warnings", []) or [] if str(item).strip()])
    warning_text = "；".join([text for text in [fallback_reason, *graph_warnings] if text])
    graph_status = "已生成"
    if graph_data.get("fallback"):
        graph_status = "回退生成"
    elif not graph_data:
        graph_status = "图结构缺失"
        if not warning_text:
            warning_text = "未检测到图结构数据，可能是 APK 解析失败、androguard 不可用或未能提取 DEX 图。"
    elif api_nodes == 0 and api_edges == 0 and not api_call_counts:
        graph_status = "API 图为空"
        if not warning_text:
            warning_text = "已提取 CFG / FCG，但未识别到敏感 API 调用。"
    sensitive_api_dist = ", ".join(f"{k}:{v}" for k, v in sorted(api_call_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))[:12]) or "无"
    lines = [
        f"- 图结构状态：`{graph_status}`" + (f"；原因：{warning_text}" if warning_text else ""),
        "### CFG / FCG / API 调用图",
        f"- CFG 节点数：`{int(stats.get('cfg_node_count', len(cfg.get('nodes', []) or [])))}`",
        f"- CFG 边数：`{int(stats.get('cfg_edge_count', len(cfg.get('edges', []) or [])))}`",
        f"- FCG 节点数：`{int(stats.get('fcg_node_count', len(fcg.get('nodes', []) or [])))}`",
        f"- FCG 边数：`{int(stats.get('fcg_edge_count', len(fcg.get('edges', []) or [])))}`",
        f"- FCG 密度：`{float(density):.4f}`" if density is not None else "- FCG 密度：`-`",
        f"- API 调用图节点数：`{int(stats.get('api_graph_node_count', len(api_graph.get('nodes', []) or [])))}`",
        f"- API 调用图边数：`{int(stats.get('api_graph_edge_count', len(api_graph.get('edges', []) or [])))}`",
        f"- API 总调用数：`{total_api_calls}`",
        f"- 敏感 API 调用分布：{sensitive_api_dist}",
    ]
    if api_call_counts:
        lines.append("- API 调用明细：")
        lines.extend([f"  - `{k}`：{v}" for k, v in sorted(api_call_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))[:20]])
    return lines


def _markdown_apk_consistency_block(report: DetectionReport) -> list[str]:
    arbitration = _coerce_arbitration_result(report.arbitration_result)
    if not arbitration:
        apk = report.target_ir.apk
        arbitration = _coerce_arbitration_result(getattr(apk, "arbitration_result", None)) if apk else None
    if not arbitration:
        return [
            "- 一致性分析结果：未获取到仲裁/一致性结果，但本次报告已显式展示缺失原因。",
            "- 一致性分数：`-`",
            "- 一致性等级：`-`",
            "- 分歧点：未获取",
            "- 被污染模块：未获取",
        ]
    lines = [
        f"- 一致性分数：`{arbitration.get('consistency_score', '-')}`",
        f"- 一致性等级：`{str(arbitration.get('consistency_level', '-') or '-').upper()}`",
    ]
    discrepancies = list(arbitration.get("discrepancies", []) or [])
    suspected = list(arbitration.get("suspected_compromised", []) or [])
    lines.append(f"- 分歧点：{', '.join(discrepancies) if discrepancies else '无'}")
    lines.append(f"- 被污染模块：{', '.join(suspected) if suspected else '无'}")
    return lines


def _markdown_apk_robustness_block(report: DetectionReport) -> list[str]:
    apk = report.target_ir.apk
    robustness = getattr(apk, "robustness", None) if apk else None
    if not robustness:
        return []
    techniques = list(getattr(robustness, "adversarial_techniques", []) or [])
    score = getattr(robustness, "robustness_score", '-')
    return [
        f"- 对抗技术：{', '.join(techniques) if techniques else '无'}",
        f"- 鲁棒性分数：`{score}`",
        f"- 抗干扰能力评估：**{_robustness_assessment(score, techniques)}**",
    ]


def _render_arbitration_block(report: DetectionReport) -> str:
    result = _coerce_arbitration_result(report.arbitration_result)
    if not result:
        return ""
    discrepancies = "<br>".join(html.escape(item) for item in result.get("discrepancies", [])) or "无"
    compromised = ", ".join(html.escape(item) for item in result.get("suspected_compromised", [])) or "无"
    return f"""
      <div style='height:14px'></div>
      <div class='panel' style='box-shadow:none; background: rgba(255,255,255,.02);'>
        <div class='panel-inner'>
          <h4 style='margin-top:0;'>仲裁结果</h4>
          <table class='table'>
            <tr><th>一致性分数</th><td>{result.get('consistency_score', '-')}</td></tr>
            <tr><th>一致性等级</th><td>{html.escape(str(result.get('consistency_level', '-')))}</td></tr>
            <tr><th>加权置信度</th><td>{result.get('weighted_confidence', '-')}</td></tr>
            <tr><th>疑似污染源</th><td>{compromised}</td></tr>
            <tr><th>分歧与模式</th><td>{discrepancies}</td></tr>
          </table>
        </div>
      </div>
    """


def _markdown_arbitration_block(report: DetectionReport) -> list[str]:
    result = _coerce_arbitration_result(report.arbitration_result)
    if not result:
        return []
    lines = [
        f"- 一致性分数：`{result.get('consistency_score', '-')}`",
        f"- 一致性等级：`{result.get('consistency_level', '-')}`",
        f"- 加权置信度：`{result.get('weighted_confidence', '-')}`",
        f"- 疑似污染源：{', '.join(result.get('suspected_compromised', [])) if result.get('suspected_compromised') else '无'}",
    ]
    if result.get("discrepancies"):
        lines.append("- 分歧与模式：")
        lines.extend([f"  - {item}" for item in result.get("discrepancies", [])])
    return lines


def _coerce_arbitration_result(value) -> dict:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    return {
        "consistency_score": getattr(value, "consistency_score", None),
        "consistency_level": getattr(value, "consistency_level", None),
        "discrepancies": list(getattr(value, "discrepancies", []) or []),
        "suspected_compromised": list(getattr(value, "suspected_compromised", []) or []),
        "weighted_confidence": getattr(value, "weighted_confidence", None),
    }


def _markdown_browser_evidence(report: DetectionReport) -> list[str]:
    lines: list[str] = []
    evidence = report.page_summary if isinstance(report.page_summary, dict) else {}
    if evidence.get("fetch_mode"):
        lines.append(f"- 抓取模式：`{evidence.get('fetch_mode')}`")
    if evidence.get("proxy_used") is not None:
        lines.append(f"- 代理是否参与：`{bool(evidence.get('proxy_used'))}`")
    return lines


def _apk_graph_data_map(graph_data):
    if not graph_data:
        return {}
    if isinstance(graph_data, dict):
        return graph_data

    # 兼容未来可能直接传入 GraphStructure 数据类的情况。
    mapped = {
        "cfg": {"nodes": getattr(graph_data, "cfg_nodes", []) or [], "edges": getattr(graph_data, "edges", []) or []},
        "fcg": {"nodes": getattr(graph_data, "fcg_nodes", []) or [], "edges": getattr(graph_data, "fcg_edges", []) or []},
        "api_graph": {
            "nodes": getattr(graph_data, "api_graph_nodes", []) or [],
            "edges": getattr(graph_data, "api_graph_edges", []) or [],
            "api_call_counts": getattr(graph_data, "api_call_counts", {}) or {},
        },
        "stats": getattr(graph_data, "graph_stats", {}) or {},
    }
    return mapped


def _consistency_level_style(consistency_level: str) -> tuple[str, str]:
    level = (consistency_level or "").lower()
    if level == "high":
        return "HIGH", "#16a34a"
    if level == "medium":
        return "MEDIUM", "#f59e0b"
    if level == "low":
        return "LOW", "#dc2626"
    return (level.upper() if level else "UNKNOWN"), "#64748b"


def _robustness_assessment(score, techniques: Sequence[str]) -> str:
    technique_count = len([item for item in techniques if str(item).strip()])
    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        numeric_score = None

    if technique_count >= 3:
        return "弱"
    if technique_count >= 1:
        return "中"
    if numeric_score is not None:
        if numeric_score < 40:
            return "弱"
        if numeric_score < 70:
            return "中"
    return "强"


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


def _encode_image_data_uri(path: Path) -> str:
    try:
        if not path.exists() or not path.is_file():
            return ""
        mime_type, _ = mimetypes.guess_type(path.name)
        if not mime_type or not mime_type.startswith("image/"):
            return ""
        return f"data:{mime_type};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"
    except Exception:
        return ""
