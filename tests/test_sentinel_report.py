from pathlib import Path

from SentinelGuard.judgement import run_detection, run_deep_url_detection_from_static
from SentinelGuard.report import save_detection_report


def test_report_files_are_generated(tmp_path):
    report = run_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    save_detection_report(report, output_dir=tmp_path)

    html_path = Path(report.html_report_path)
    md_path = Path(report.markdown_report_path)

    assert html_path.exists()
    assert md_path.exists()
    html_text = html_path.read_text(encoding="utf-8")
    md_text = md_path.read_text(encoding="utf-8")

    assert "SentinelGuard 哨塔检测报告" in html_text
    assert "风险证据" in html_text
    assert "处置建议" in md_text
    assert "静态检测报告" in html_text


def test_apk_report_mentions_apk_summary(tmp_path):
    report = run_detection("sample.apk", target_type="apk")
    save_detection_report(report, output_dir=tmp_path)

    html_text = Path(report.html_report_path).read_text(encoding="utf-8")
    md_text = Path(report.markdown_report_path).read_text(encoding="utf-8")

    assert report.target_ir.target_type == "apk"
    assert "sentinel_report_apk_static_" in report.html_report_path
    assert "sentinel_report_apk_static_" in report.markdown_report_path
    assert report.target_ir.apk.file_name == "sample.apk"


def test_deep_report_mentions_parent_report(monkeypatch, tmp_path):
    from SentinelGuard import judgement

    monkeypatch.setattr(judgement, "deep_analyze_url", lambda _report: {
        "risk_level": "high",
        "score": 72,
        "expert_opinions": {
            "主持人": "模型判断目标存在高风险。",
            "静态分析员": "静态规则命中较多。",
            "行为分析员": "页面行为可疑。",
            "情报分析员": "未接入外部情报。",
            "处置建议员": "建议阻断。",
        },
        "additional_findings": [],
    })

    static_report = run_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    save_detection_report(static_report, output_dir=tmp_path)
    deep_report = run_deep_url_detection_from_static(static_report, persist_report=False)
    save_detection_report(deep_report, output_dir=tmp_path)

    html_text = Path(deep_report.html_report_path).read_text(encoding="utf-8")
    md_text = Path(deep_report.markdown_report_path).read_text(encoding="utf-8")

    assert "模型深度检查报告" in html_text
    assert "关联静态 HTML 报告" in html_text
    assert "模型深度研判" in md_text
