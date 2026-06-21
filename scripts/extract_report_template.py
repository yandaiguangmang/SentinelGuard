from pathlib import Path
import re


REPORT_PATH = Path("SentinelGuard/report.py")
TEMPLATE_PATH = Path("templates/report_template.html")


def main() -> None:
    text = REPORT_PATH.read_text(encoding="utf-8")
    start = text.index("def render_html_report(report: DetectionReport) -> str:")
    marker = "def render_markdown_report(report: DetectionReport) -> str:"
    end = text.index(marker)
    func_text = text[start:end]
    match = re.search(r'return f"""(.*)"""\s*$', func_text, re.S)
    if not match:
        raise SystemExit("Could not locate HTML f-string in render_html_report")

    body = match.group(1)
    replacements = [
        ("{'深度研判' if report.analysis_mode == 'deep' else '静态研判'}", "${analysis_mode_chip}"),
        ("{len(report.findings)}", "${finding_count}"),
        ("{'danger' if report.risk_level in {'high', 'critical'} else 'warning' if report.risk_level == 'medium' else 'success'}", "${risk_chip_class}"),
        ("{html.escape(report.risk_level.upper())}", "${risk_level_upper}"),
        ("{summary_cards}", "${summary_cards}"),
        ("{result_panel}", "${result_panel}"),
        ("{artifact_panel}", "${artifact_panel}"),
        ("{chain_panel}", "${chain_panel}"),
        ("{findings_panel}", "${findings_panel}"),
        ("{discussion_panel}", "${discussion_panel}"),
        ("{model_panel}", "${model_panel}"),
        ("{placeholders_panel}", "${placeholders_panel}"),
        ("{analysis_mode_label}", "${analysis_mode_label}"),
        ("{parent_report_block}", "${parent_report_block}"),
        ("{browser_evidence_block}", "${browser_evidence_block}"),
        ("{apk_dynamic_block}", "${apk_dynamic_block}"),
        ("{apk_graph_block}", "${apk_graph_block}"),
        ("{apk_consistency_block}", "${apk_consistency_block}"),
        ("{apk_robustness_block}", "${apk_robustness_block}"),
        ("{arbitration_block}", "${arbitration_block}"),
        ("{role_limitations_block}", "${role_limitations_block}"),
        ("{'模型深度研判' if report.analysis_mode == 'deep' else 'APK 动态协同研判' if report.analysis_mode == 'dynamic' else '协同研判'}", "${discussion_title}"),
        ("{_render_screenshot_block(report)}", "${screenshot_block}"),
        ("{_render_stats_block(report)}", "${stats_block}"),
        ("{_risk_color(report.risk_level)}", "${risk_color}"),
    ]
    for old, new in replacements:
        body = body.replace(old, new)

    TEMPLATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    TEMPLATE_PATH.write_text(body, encoding="utf-8")
    print(f"wrote {TEMPLATE_PATH}")


if __name__ == "__main__":
    main()