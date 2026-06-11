from pathlib import Path

from SentinelGuard.judgement import run_deep_url_detection_from_static, run_static_detection
from SentinelGuard.state import DetectionFinding


class FakeDeepAnalyzerResponse:
    @staticmethod
    def build():
        return {
            "risk_level": "high",
            "score": 78,
            "expert_opinions": {
                "主持人": "综合静态结果与页面线索，目标存在较高风险。",
                "静态分析员": "静态规则命中了登录诱导与跳转线索。",
                "行为分析员": "跳转链和表单行为存在敏感凭据收集风险。",
                "情报分析员": "未接入外部情报，但当前证据已足够支持高风险判断。",
                "处置建议员": "建议阻断访问并保留报告。",
            },
            "additional_findings": [
                DetectionFinding(
                    rule_id="DEEP_ROLE_CONSENSUS",
                    title="多角色研判形成高风险共识",
                    severity="high",
                    description="模型认为多个角色对钓鱼风险形成一致判断。",
                    evidence="主持人、行为分析员、处置建议员均建议阻断。",
                    recommendation="将该链接作为高风险目标处理。",
                )
            ],
        }


def test_run_deep_url_detection_from_static(monkeypatch, tmp_path):
    from SentinelGuard import judgement

    monkeypatch.setattr(judgement, "deep_analyze_url", lambda _report: FakeDeepAnalyzerResponse.build())

    static_report = run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    static_report.html_report_path = "sentinel_reports/static.html"
    static_report.markdown_report_path = "sentinel_reports/static.md"

    deep_report = run_deep_url_detection_from_static(static_report, persist_report=False)

    assert deep_report.analysis_mode == "deep"
    assert deep_report.deep_analysis_used is True
    assert deep_report.parent_html_report_path == "sentinel_reports/static.html"
    assert deep_report.parent_markdown_report_path == "sentinel_reports/static.md"
    assert deep_report.risk_level == "high"
    assert any(f.rule_id == "DEEP_ROLE_CONSENSUS" for f in deep_report.findings)
    assert "主持人" in deep_report.expert_opinions


def test_deep_report_files_include_mode(monkeypatch, tmp_path):
    from SentinelGuard import judgement
    from SentinelGuard.report import save_detection_report

    monkeypatch.setattr(judgement, "deep_analyze_url", lambda _report: FakeDeepAnalyzerResponse.build())

    static_report = run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    save_detection_report(static_report, output_dir=tmp_path)
    deep_report = run_deep_url_detection_from_static(static_report, persist_report=False)
    save_detection_report(deep_report, output_dir=tmp_path)

    assert Path(static_report.html_report_path).name.startswith("sentinel_report_url_static_")
    assert Path(deep_report.html_report_path).name.startswith("sentinel_report_url_deep_")
