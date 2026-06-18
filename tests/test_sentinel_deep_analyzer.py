import json
from pathlib import Path

from SentinelGuard.analyzers.url_deep_analyzer import URLDeepAnalyzer, _load_json_payload
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


class FakeLowRiskDeepAnalyzerResponse:
    @staticmethod
    def build():
        return {
            "risk_level": "low",
            "score": 92,
            "summary": "主持人认为当前目标整体风险不高，建议仅做常规复核。",
            "expert_opinions": {
                "主持人": "主持人认为整体风险不高。",
                "静态分析员": "静态规则命中较少。",
                "行为分析员": "未观察到明显恶意行为链。",
                "情报分析员": "离线证据不足以支撑高风险判断。",
                "处置建议员": "建议常规复核即可。",
            },
            "additional_findings": [],
        }


def test_run_deep_url_detection_from_static(monkeypatch, tmp_path):
    from SentinelGuard import judgement

    monkeypatch.setattr(judgement, "deep_analyze_url", lambda *_args, **_kwargs: FakeDeepAnalyzerResponse.build())

    static_report = run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    static_report.html_report_path = "sentinel_reports/static.html"
    static_report.markdown_report_path = "sentinel_reports/static.md"

    deep_report = run_deep_url_detection_from_static(static_report, persist_report=False)

    assert deep_report.analysis_mode == "deep"
    assert deep_report.deep_analysis_used is True
    assert deep_report.parent_html_report_path == "sentinel_reports/static.html"
    assert deep_report.parent_markdown_report_path == "sentinel_reports/static.md"
    assert deep_report.risk_level in {"high", "critical"}
    assert 0 < deep_report.score <= 100
    assert any(f.rule_id == "DEEP_ROLE_CONSENSUS" for f in deep_report.findings)
    assert "主持人" in deep_report.expert_opinions


def test_deep_score_respects_low_risk_host_summary(monkeypatch):
    from SentinelGuard import judgement

    monkeypatch.setattr(judgement, "deep_analyze_url", lambda *_args, **_kwargs: FakeLowRiskDeepAnalyzerResponse.build())

    static_report = run_static_detection("https://www.zhihu.com/", fetch_page=False)
    static_report.html_report_path = "sentinel_reports/static.html"
    static_report.markdown_report_path = "sentinel_reports/static.md"

    deep_report = run_deep_url_detection_from_static(static_report, persist_report=False)

    assert deep_report.risk_level in {"low", "medium", "high"}
    assert deep_report.score < 90
    assert deep_report.score <= static_report.score or deep_report.risk_level in {"low", "medium"}


def test_deep_report_files_include_mode(monkeypatch, tmp_path):
    from SentinelGuard import judgement
    from SentinelGuard.report import save_detection_report

    monkeypatch.setattr(judgement, "deep_analyze_url", lambda *_args, **_kwargs: FakeDeepAnalyzerResponse.build())

    static_report = run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    save_detection_report(static_report, output_dir=tmp_path)
    deep_report = run_deep_url_detection_from_static(static_report, persist_report=False)
    save_detection_report(deep_report, output_dir=tmp_path)

    assert Path(static_report.html_report_path).name.startswith("sentinel_report_url_static_")
    assert Path(deep_report.html_report_path).name.startswith("sentinel_report_url_deep_")


def test_host_payload_serializes_role_outputs(monkeypatch):
    monkeypatch.setattr(URLDeepAnalyzer, "_build_client", lambda self, role: object())

    analyzer = URLDeepAnalyzer()
    payload = analyzer._build_host_payload(
        static_report=run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False),
        role_outputs={
            "静态分析员": {
                "opinion": "静态证据命中",
                "risk_hint": "high",
                "additional_findings": [
                    DetectionFinding(
                        rule_id="DEEP_STATIC_JSON",
                        title="序列化回归测试",
                        severity="high",
                        description="确保深度分析结果可被 JSON 编码。",
                        evidence="role_outputs contains DetectionFinding",
                        recommendation="应先转换为 dict 再进入 host payload。",
                    )
                ],
            }
        },
    )

    assert payload["role_outputs"]["静态分析员"]["additional_findings"][0]["rule_id"] == "DEEP_STATIC_JSON"
    json.dumps(payload, ensure_ascii=False)


def test_host_payload_includes_browser_evidence(monkeypatch):
    monkeypatch.setattr(URLDeepAnalyzer, "_build_client", lambda self, role: object())

    static_report = run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    static_report.redirect_chain = ["http://example.com/login", "https://safe.example/login"]
    static_report.page_summary = {
        "title": "Login",
        "visible_text_excerpt": "请输入账号密码 立即登录",
        "html_summary": {
            "raw_excerpt": "<html><body>请输入账号密码 立即登录</body></html>",
            "text_excerpt": "请输入账号密码 立即登录",
        },
        "password_forms": 1,
        "hidden_inputs": 2,
        "meta_refresh": ["0;url=https://evil.example"],
        "download_links": ["tool.apk"],
        "external_script_count": 3,
        "form_actions": ["/login"],
        "script_srcs": ["https://cdn.example/app.js"],
        "status_code": 200,
        "content_type": "text/html; charset=utf-8",
        "final_url": "https://safe.example/login",
        "fetch_mode": "proxy",
        "proxy_used": True,
    }

    analyzer = URLDeepAnalyzer()
    payload = analyzer._build_host_payload(
        static_report=static_report,
        role_outputs={},
    )

    browser_evidence = payload["browser_evidence"]
    assert browser_evidence["has_page_fetch"] is True
    assert browser_evidence["final_url"] == "https://safe.example/login"
    assert browser_evidence["page_signals"]["title"] == "Login"
    assert browser_evidence["page_signals"]["visible_text_excerpt"] == "请输入账号密码 立即登录"
    assert browser_evidence["page_signals"]["html_summary"]["raw_excerpt"].startswith("<html><body>")
    assert browser_evidence["page_signals"]["download_links"] == ["tool.apk"]
    assert "HTML摘要=" in browser_evidence["browser_observation"]
    json.dumps(payload, ensure_ascii=False)


def test_build_messages_include_browser_evidence_text(monkeypatch):
    monkeypatch.setattr(URLDeepAnalyzer, "_build_client", lambda self, role: object())

    static_report = run_static_detection("http://example.com/login?redirect=http://evil.test", fetch_page=False)
    static_report.redirect_chain = ["http://example.com/login", "https://safe.example/login"]
    static_report.page_summary = {
        "title": "Login",
        "visible_text_excerpt": "请输入账号密码 立即登录",
        "html_summary": {"raw_excerpt": "<html><body>请输入账号密码 立即登录</body></html>"},
        "status_code": 200,
        "content_type": "text/html; charset=utf-8",
        "final_url": "https://safe.example/login",
    }

    analyzer = URLDeepAnalyzer()
    payload = analyzer._build_payload(static_report)
    messages = analyzer._build_messages("静态分析员", payload)

    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert isinstance(messages[1]["content"], str)
    assert "Browser evidence" not in messages[1]["content"]
    assert "HTML摘要=" in messages[1]["content"]


def test_deep_analyzer_tolerates_non_dict_findings(monkeypatch):
    from SentinelGuard.analyzers import url_deep_analyzer

    analyzer = URLDeepAnalyzer()
    analyzer.role_clients = {role: object() for role in url_deep_analyzer.DEEP_ROLE_ORDER}

    role_result = {
        "success": True,
        "content": json.dumps({
            "opinion": "静态分析员输出正常。",
            "risk_hint": "high",
            "additional_findings": [
                "unexpected text finding",
                {
                    "rule_id": "DEEP_TEXT_DICT",
                    "title": "字典结构项",
                    "severity": "critical",
                    "description": "",
                    "evidence": "evidence",
                    "recommendation": "review",
                },
            ],
        }, ensure_ascii=False),
    }

    normalized_role = analyzer._normalize_role_output("静态分析员", role_result)
    assert normalized_role["opinion"] == "静态分析员输出正常。"
    assert len(normalized_role["additional_findings"]) == 2
    assert normalized_role["additional_findings"][0].severity == "medium"

    host_result = {
        "success": True,
        "content": json.dumps({
            "risk_level": "high",
            "score": 70,
            "summary": "主持人总结。",
            "expert_opinions": {
                "主持人": "主持人总结。",
                "静态分析员": "静态分析员输出正常。",
                "行为分析员": "行为分析员补充。",
                "情报分析员": "情报分析员补充。",
                "处置建议员": "处置建议员补充。",
            },
            "expert_models": {
                "主持人": "model-a",
                "静态分析员": "model-b",
                "行为分析员": "model-c",
                "情报分析员": "model-d",
                "处置建议员": "model-e",
            },
            "additional_findings": ["host text finding"],
        }, ensure_ascii=False),
    }

    report = run_static_detection("https://baksmany.org/", fetch_page=False)
    normalized = analyzer._normalize_result(host_result, report, {"静态分析员": normalized_role})

    assert normalized["risk_level"] == "high"
    assert 0 <= normalized["score"] <= 100
    assert normalized["expert_opinions"]["静态分析员"] == "静态分析员输出正常。"
    assert any(f.evidence == "host text finding" for f in normalized["additional_findings"])


def test_load_json_payload_accepts_code_fenced_and_mixed_text():
    fenced = """说明文字\n```json\n{\"opinion\": \"ok\", \"risk_hint\": \"high\"}\n```\n尾部说明"""
    mixed = "前缀文本 {\"opinion\": \"ok2\", \"risk_hint\": \"medium\"} 后缀文本"
    list_payload = json.dumps([
        "not-an-object",
        {"opinion": "ok3", "risk_hint": "critical"},
    ], ensure_ascii=False)

    fenced_data = _load_json_payload(fenced)
    mixed_data = _load_json_payload(mixed)
    list_data = _load_json_payload(list_payload)

    assert fenced_data["opinion"] == "ok"
    assert fenced_data["risk_hint"] == "high"
    assert mixed_data["opinion"] == "ok2"
    assert mixed_data["risk_hint"] == "medium"
    assert list_data["opinion"] == "ok3"
    assert list_data["risk_hint"] == "critical"
