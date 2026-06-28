import json
import os
from pathlib import Path

from config import settings
from SentinelGuard.analyzers.apk_deep_analyzer import APKDeepAnalyzer
from SentinelGuard.judgement import run_apk_dynamic_detection_from_static
from SentinelGuard.analyzers.url_deep_analyzer import URLDeepAnalyzer, _load_json_payload
from SentinelGuard.judgement import run_deep_url_detection_from_static, run_static_detection
from SentinelGuard.state import APKIR, DetectionFinding, DetectionReport, TargetIR


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
    assert deep_report.risk_level in {"medium", "high", "critical"}
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


def test_apk_deep_payload_trims_large_apk_fields():
    apk_ir = APKIR(
        normalized_path="demo.apk",
        file_name="demo.apk",
        package_name="com.example.demo",
        extracted_strings=[f"string_{i}" for i in range(300)],
        key_files=[f"file_{i}.dex" for i in range(80)],
        evidence_summary={
            "file_count": 80,
            "files": [f"file_{i}.dex" for i in range(80)],
            "warnings": [f"warn_{i}" for i in range(20)],
            "summary": {"demo": True},
        },
        graph_data={
            "cfg": {
                "nodes": [{"id": i, "name": f"cfg_{i}"} for i in range(50)],
                "edges": [{"src": 0, "dst": i} for i in range(50)],
            },
            "fcg": {
                "nodes": [{"id": i, "name": f"fcg_{i}"} for i in range(40)],
                "edges": [{"src": 1, "dst": i} for i in range(40)],
            },
            "api_graph": {
                "nodes": [{"id": i, "name": f"api_{i}"} for i in range(30)],
                "edges": [{"src": 2, "dst": i} for i in range(30)],
                "api_call_counts": {f"Lapi/{i};->call()V": i for i in range(30)},
            },
            "warnings": [f"graph_warn_{i}" for i in range(12)],
            "stats": {"cfg_nodes": 50, "cfg_edges": 50},
        },
    )
    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input="demo.apk", status="ready", apk=apk_ir),
        risk_level="medium",
        score=55,
        findings=[],
        expert_opinions={"主持人": "ok", "静态分析员": "ok", "行为分析员": "ok", "情报分析员": "ok", "处置建议员": "ok"},
    )

    analyzer = APKDeepAnalyzer()
    payload = analyzer._build_payload(static_report)
    host_payload = analyzer._build_host_payload(static_report, {})

    apk_payload = payload["apk_ir"]
    assert apk_payload["extracted_strings_count"] == 300
    assert len(apk_payload["extracted_strings"]) == 5
    assert len(apk_payload["key_files"]) == 12
    assert apk_payload["key_files_count"] == 80
    assert len(apk_payload["evidence_summary"]["files_preview"]) == 12
    assert "files" not in apk_payload["evidence_summary"]
    assert apk_payload["graph_data"]["cfg"]["node_count"] == 50
    assert len(apk_payload["graph_data"]["cfg"]["nodes_preview"]) == 12
    assert "nodes" not in apk_payload["graph_data"]["cfg"]
    assert len(apk_payload["graph_data"]["api_graph"]["api_call_counts_top"]) == 12


def test_apk_deep_payload_excludes_source_path_from_model_input():
    apk_ir = APKIR(
        normalized_path=r"C:\\Temp\\sentinel_uploads\\sample.apk",
        file_name="sample.apk",
        package_name="com.example.sample",
        sha256="a" * 64,
        size_bytes=123456,
    )
    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input=r"C:\\Temp\\sentinel_uploads\\sample.apk", status="ready", apk=apk_ir),
        risk_level="medium",
        score=55,
        findings=[],
        expert_opinions={"主持人": "ok", "静态分析员": "ok", "行为分析员": "ok", "情报分析员": "ok", "处置建议员": "ok"},
    )

    analyzer = APKDeepAnalyzer()
    payload = analyzer._build_payload(static_report)
    intel_payload = analyzer._build_role_payload("情报分析员", static_report, payload)

    assert "normalized_path" not in payload["apk_ir"]
    assert "normalized_path" not in payload["target"]["apk"]
    assert "C:\\Temp\\sentinel_uploads\\sample.apk" not in json.dumps(payload, ensure_ascii=False)
    assert "C:\\Temp\\sentinel_uploads\\sample.apk" not in analyzer._summarize_host_evidence_source(static_report)
    assert "C:\\Temp\\sentinel_uploads\\sample.apk" not in json.dumps(intel_payload, ensure_ascii=False)

    assert set(host_payload.keys()) == {"role_outputs"}
    assert host_payload["role_outputs"] == {}
    json.dumps(payload, ensure_ascii=False)
    json.dumps(host_payload, ensure_ascii=False)


def test_apk_deep_payload_recursive_compression_under_80kb():
    analyzer = APKDeepAnalyzer()
    payload = {
        "target": {
            "original_input": "A" * 5000,
            "apk": {
                "file_name": "demo.apk",
                "package_name": "com.example.demo",
                "evidence_summary": {
                    "files": [f"file_{i}_{'B' * 6000}" for i in range(30)],
                    "warnings": [f"warn_{i}_{'C' * 3000}" for i in range(20)],
                    "summary": {"blob": "D" * 40000},
                },
                "graph_data": {
                    "cfg": {
                        "nodes": [{"id": i, "name": f"node_{i}_{'E' * 4000}"} for i in range(20)],
                        "edges": [{"src": i, "dst": i + 1, "label": "L" * 4000} for i in range(20)],
                    },
                },
            },
        },
        "static_report": {
            "apk_summary": {
                "suspicious_strings": [f"S{i}_{'F' * 5000}" for i in range(20)],
            },
            "expert_opinions": {
                "主持人": "G" * 30000,
                "静态分析员": "H" * 30000,
                "行为分析员": "I" * 30000,
                "情报分析员": "J" * 30000,
                "处置建议员": "K" * 30000,
            },
        },
        "role_outputs": {
            "静态分析员": {"opinion": "L" * 50000, "additional_findings": []},
            "行为分析员": {"opinion": "M" * 50000, "additional_findings": []},
        },
    }

    initial_size = analyzer._payload_size_bytes(payload)
    assert initial_size > 80 * 1024

    compressed = analyzer._ensure_payload_within_limit("test", payload)
    compressed_size = analyzer._payload_size_bytes(compressed)

    assert compressed_size <= 80 * 1024
    assert len(compressed["target"]["original_input"]) <= 1200
    assert "evidence_summary" not in compressed["target"]["apk"] or isinstance(compressed["target"]["apk"]["evidence_summary"], dict)
    assert "graph_data" not in compressed["target"]["apk"] or isinstance(compressed["target"]["apk"]["graph_data"], dict)
    assert len(compressed["role_outputs"]["静态分析员"]["opinion"]) <= 1200


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


def test_apk_dynamic_full_pipeline_with_real_sample(monkeypatch):
    apk_path = Path(r"G:\testcases\apk\Yahnac.apk")
    assert apk_path.exists(), f"测试样本不存在: {apk_path}"

    static_report = run_static_detection(str(apk_path), target_type="apk")
    assert static_report.target_ir.target_type == "apk"
    assert static_report.target_ir.apk is not None
    assert static_report.target_ir.apk.file_name == "Yahnac.apk"

    # 允许通过环境变量控制动态沙箱运行时长，默认给足够时间跑完整阶段
    runtime_window_seconds = int(os.getenv("APK_DYNAMIC_TEST_WINDOW_SECONDS", "12"))
    monkeypatch.setattr(settings, "APK_DYNAMIC_RUNTIME_WINDOW_SECONDS", runtime_window_seconds, raising=False)

    observed_stages: list[str] = []

    def _progress_callback(stage: str, _message: str, _progress: int) -> None:
        observed_stages.append(stage)

    dynamic_report = run_apk_dynamic_detection_from_static(
        static_report,
        persist_report=False,
        progress_callback=_progress_callback,
    )

    assert dynamic_report.analysis_mode == "dynamic"
    assert dynamic_report.deep_analysis_used is True
    assert dynamic_report.target_ir.target_type == "apk"
    assert dynamic_report.target_ir.apk is not None
    assert dynamic_report.target_ir.apk.file_name == "Yahnac.apk"
    assert "主持人" in dynamic_report.expert_opinions
    assert "静态分析员" in dynamic_report.expert_opinions
    assert "行为分析员" in dynamic_report.expert_opinions
    assert "情报分析员" in dynamic_report.expert_opinions
    assert "处置建议员" in dynamic_report.expert_opinions
    assert dynamic_report.apk_dynamic_summary is not None
    assert dynamic_report.apk_dynamic_artifacts is not None
    assert dynamic_report.html_report_path is None or isinstance(dynamic_report.html_report_path, str)
    assert any(stage == "dynamic_prepare" for stage in observed_stages)
    assert any(stage == "dynamic_install" for stage in observed_stages)
    assert any(stage == "dynamic_launch" for stage in observed_stages)
    assert any(stage == "deep_intel" for stage in observed_stages)
    assert any(stage == "deep_advice" for stage in observed_stages)
    assert observed_stages[-1] in {"deep_advice", "deep_done", "dynamic_launch", "deep_intel"}