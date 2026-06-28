from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory



ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from SentinelGuard.analyzers.apk_graph_extractor import APKGraphExtractor
import SentinelGuard.analyzers.apk_analyzer as apk_analyzer_module
import SentinelGuard.analyzers.apk_graph_extractor as apk_graph_extractor_module
from SentinelGuard.arbitrator import Arbitrator
from SentinelGuard.robustness_validator import RobustnessValidator
from SentinelGuard.scoring import combine_apk_scores, combine_scores
from SentinelGuard.report import _markdown_apk_robustness_block, _top_level_adversarial_techniques
from SentinelGuard.report import _apk_graph_data_map
from SentinelGuard.state import APKIR, DetectionFinding, DetectionReport, GraphStructure, TargetIR


def test_graph_extractor() -> None:
    """用一个小样本 APK 触发图提取，并打印节点数/边数。"""

    extractor = APKGraphExtractor()
    sample_apk_summary = {
        "package_name": "com.example.demo",
        "file_name": "demo.apk",
    }

    graph_data = extractor.extract_all(None, sample_apk_summary)
    stats = graph_data.get("stats", {}) if isinstance(graph_data, dict) else {}

    cfg_nodes = int(stats.get("cfg_node_count", len(graph_data.get("cfg", {}).get("nodes", []))))
    cfg_edges = int(stats.get("cfg_edge_count", len(graph_data.get("cfg", {}).get("edges", []))))
    fcg_nodes = int(stats.get("fcg_node_count", len(graph_data.get("fcg", {}).get("nodes", []))))
    fcg_edges = int(stats.get("fcg_edge_count", len(graph_data.get("fcg", {}).get("edges", []))))

    print("[graph_extractor]")
    print(f"CFG nodes: {cfg_nodes}, CFG edges: {cfg_edges}")
    print(f"FCG nodes: {fcg_nodes}, FCG edges: {fcg_edges}")
    print(f"API graph nodes: {int(stats.get('api_graph_node_count', 0))}, API graph edges: {int(stats.get('api_graph_edge_count', 0))}")

    assert cfg_nodes >= 1
    assert fcg_nodes >= 1


def test_graph_extractor_multi_dex_merge() -> None:
    """验证多段 DEX 输入不会被拼接成无效字节串，而是逐段解析并合并方法图。"""

    original_dalvik_vm_format = apk_graph_extractor_module.DalvikVMFormat

    class FakeInstruction:
        def __init__(self, name: str, output: str = "") -> None:
            self._name = name
            self._output = output or name

        def get_name(self) -> str:
            return self._name

        def get_output(self) -> str:
            return self._output

    class FakeCode:
        def __init__(self, instructions) -> None:
            self._instructions = instructions

        def get_bc(self):
            return self

        def get_instructions(self):
            return list(self._instructions)

    class FakeMethod:
        def __init__(self, class_name: str, name: str, descriptor: str, instructions) -> None:
            self._class_name = class_name
            self._name = name
            self._descriptor = descriptor
            self._code = FakeCode(instructions)

        def get_class_name(self) -> str:
            return self._class_name

        def get_name(self) -> str:
            return self._name

        def get_descriptor(self) -> str:
            return self._descriptor

        def get_code(self):
            return self._code

    class FakeVM:
        def __init__(self, methods) -> None:
            self._methods = methods

        def get_methods(self):
            return list(self._methods)

    class FakeDalvikVMFormat:
        def __init__(self, dex_bytes: bytes) -> None:
            if dex_bytes == b"dex1":
                self._methods = [
                    FakeMethod(
                        "Lcom/example/A;",
                        "foo",
                        "()V",
                        [FakeInstruction("const-string"), FakeInstruction("return-void")],
                    )
                ]
            elif dex_bytes == b"dex2":
                self._methods = [
                    FakeMethod(
                        "Lcom/example/B;",
                        "bar",
                        "()V",
                        [FakeInstruction("invoke-virtual", "invoke-virtual Lcom/example/A;->foo()V"), FakeInstruction("return-void")],
                    )
                ]
            else:
                raise ValueError("unexpected dex payload")

        def get_methods(self):
            return list(self._methods)

    try:
        apk_graph_extractor_module.DalvikVMFormat = FakeDalvikVMFormat
        extractor = APKGraphExtractor()
        graph_data = extractor.extract_all([b"dex1", b"dex2"], {"package_name": "com.example.demo", "file_name": "demo.apk"})
        stats = graph_data.get("stats", {}) if isinstance(graph_data, dict) else {}

        print("[graph_extractor_multi_dex]")
        print(f"fallback: {graph_data.get('fallback')}")
        print(f"cfg_node_count: {stats.get('cfg_node_count')}")
        print(f"fcg_node_count: {stats.get('fcg_node_count')}")
        print(f"fcg_edge_count: {stats.get('fcg_edge_count')}")

        assert graph_data.get("fallback") is not True
        assert int(stats.get("cfg_node_count", 0)) >= 2
        assert int(stats.get("fcg_node_count", 0)) >= 2
        assert int(stats.get("fcg_edge_count", 0)) >= 1
    finally:
        apk_graph_extractor_module.DalvikVMFormat = original_dalvik_vm_format


def test_apk_graph_data_map_preserves_graph_structure_metadata() -> None:
    """验证 GraphStructure 传入报告层后，新增元数据不会丢失。"""

    graph = GraphStructure(
        cfg={"nodes": [{"id": "b0"}], "edges": []},
        fcg={"nodes": [{"id": "m0"}], "edges": [{"source": "m0", "target": "m1"}]},
        api_graph={
            "nodes": [{"id": "api0"}],
            "edges": [],
            "api_call_counts": {"Landroid/telephony/SmsManager;->sendTextMessage": 3},
        },
        stats={"cfg_node_count": 1, "fcg_node_count": 1},
        fallback=True,
        fallback_reason="androguard_unavailable_or_parse_failed",
        source={"file_name": "demo.apk", "package_name": "com.example.demo"},
        warnings=["图结构提取失败：BadZipFile: File is not a zip file"],
    )

    mapped = _apk_graph_data_map(graph)

    assert mapped["fallback"] is True
    assert mapped["fallback_reason"] == "androguard_unavailable_or_parse_failed"
    assert mapped["source"]["file_name"] == "demo.apk"
    assert mapped["warnings"] == ["图结构提取失败：BadZipFile: File is not a zip file"]
    assert mapped["api_graph"]["api_call_counts"]["Landroid/telephony/SmsManager;->sendTextMessage"] == 3


def test_arbitrator() -> None:
    """模拟三组评分，验证仲裁一致性和污染源识别。"""

    arbitrator = Arbitrator()
    findings = [DetectionFinding("R1", "demo", "high", "d", "e", "r")]

    result = arbitrator.arbitrate(
        static_score=90,
        behavior_score=20,
        intelligence_score=85,
        static_findings=findings,
        behavior_findings=[],
        intelligence_findings=findings,
    )

    print("[arbitrator]")
    print(f"consistency_score: {result.consistency_score}")
    print(f"consistency_level: {result.consistency_level}")
    print(f"discrepancies: {result.discrepancies}")
    print(f"suspected_compromised: {result.suspected_compromised}")
    print(f"weighted_confidence: {result.weighted_confidence}")

    assert result.consistency_level in {"high", "medium", "low"}
    assert result.discrepancies
    assert result.suspected_compromised


def test_robustness_validator() -> None:
    """用包含可疑关键词的模拟数据测试鲁棒性检测。"""

    validator = RobustnessValidator()
    apk_ir = APKIR(
        normalized_path="demo.apk",
        file_name="demo.apk",
        package_name="com.example.demo",
        extracted_strings=[
            "ro.kernel.qemu",
            "DexClassLoader",
            "Class.forName",
            "字符串加密",
        ],
    )
    apk_ir.graph_data = {
        "cfg": {"nodes": [{"name": "La;->a()V"}, {"name": "Lb;->b()V"}], "edges": []},
        "fcg": {"nodes": [{"name": "La;->a()V"}], "edges": []},
        "api_graph": {"nodes": [], "edges": [], "api_call_counts": {}},
        "stats": {},
    }

    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input="demo.apk", status="ok", apk=apk_ir),
        risk_level="low",
        score=10,
        findings=[DetectionFinding("R2", "suspicious", "medium", "m", "ro.kernel.qemu", "check")],
        expert_opinions={"主持人": "demo"},
    )

    result = validator.validate(static_report, apk_ir, apk_ir.graph_data)

    print("[robustness_validator]")
    print(f"adversarial_techniques: {result.adversarial_techniques}")
    print(f"robustness_score: {result.robustness_score}")
    print(f"anti_emulator_detected: {result.anti_emulator_detected}")
    print(f"obfuscation_detected: {result.obfuscation_detected}")
    print(f"reflection_detected: {result.reflection_detected}")
    print(f"dynamic_loading_detected: {result.dynamic_loading_detected}")

    assert result.adversarial_techniques
    assert result.anti_emulator_detected is True


def test_robustness_validator_detects_anti_static_analysis() -> None:
    """模拟 APK 解析失败/回退，验证抗静态检测会被命中。"""

    validator = RobustnessValidator()
    apk_ir = APKIR(
        normalized_path="broken.apk",
        file_name="broken.apk",
        package_name="com.example.broken",
        evidence_summary={
            "warnings": [
                "图结构提取失败：BadZipFile: File is not a zip file",
                "样本疑似加壳或头部格式异常",
            ]
        },
    )

    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input="broken.apk", status="ok", apk=apk_ir),
        risk_level="low",
        score=10,
        findings=[DetectionFinding("R2", "static parse fallback", "medium", "fallback", "androguard_unavailable_or_parse_failed", "check")],
        expert_opinions={"主持人": "demo"},
        apk_summary={
            "graph_warnings": ["图结构提取失败：BadZipFile: File is not a zip file"],
            "graph_summary": {"has_fallback": True},
        },
    )

    graph_data = {
        "fallback": True,
        "fallback_reason": "androguard_unavailable_or_parse_failed",
        "warnings": ["BadZipFile: File is not a zip file"],
    }

    result = validator.validate(static_report, apk_ir, graph_data)

    print("[robustness_validator_anti_static]")
    print(f"adversarial_techniques: {result.adversarial_techniques}")
    print(f"anti_static_categories: {result.anti_static_categories}")
    print(f"anti_static_detected: {result.anti_static_detected}")
    print(f"robustness_score: {result.robustness_score}")

    assert result.anti_static_detected is True
    assert "抗静态检测" in result.adversarial_techniques
    assert "伪装头部" in result.anti_static_categories
    assert "加壳" in result.anti_static_categories
    assert result.robustness_score >= 10

    top_level_techniques = _top_level_adversarial_techniques(result)
    assert "抗静态检测" in top_level_techniques
    assert "伪装头部" not in top_level_techniques
    assert "加壳" not in top_level_techniques


def test_apk_analyzer_marks_fallback_graph_on_bad_zip() -> None:
    """验证 APK 解析失败时，图结构会显式标记 fallback，从而触发鲁棒性加分。"""

    with TemporaryDirectory() as tmpdir:
        apk_path = Path(tmpdir) / "broken.apk"
        apk_path.write_bytes(b"this is not a zip archive")

        apk_ir = APKIR(normalized_path=str(apk_path), file_name="broken.apk")

        result = apk_analyzer_module._enrich_apk_ir(apk_ir)

    assert result.graph_data is not None
    assert getattr(result.graph_data, "fallback", False) is True or result.graph_data.get("fallback") is True
    fallback_reason = getattr(result.graph_data, "fallback_reason", "") if not isinstance(result.graph_data, dict) else result.graph_data.get("fallback_reason", "")
    assert "BadZipFile" in str(fallback_reason)


def test_robustness_validator_gains_bonus_on_parse_fallback() -> None:
    """验证解析失败的 fallback 图结构会提升鲁棒性分数。"""

    validator = RobustnessValidator()
    apk_ir = APKIR(
        normalized_path="broken.apk",
        file_name="broken.apk",
        package_name="com.example.broken",
    )
    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input="broken.apk", status="ok", apk=apk_ir),
        risk_level="low",
        score=10,
        findings=[],
        expert_opinions={"主持人": "demo"},
        apk_summary={"graph_summary": {"has_fallback": True}, "graph_warnings": ["图结构提取失败：BadZipFile: File is not a zip file"]},
    )
    graph_data = {
        "fallback": True,
        "fallback_reason": "BadZipFile: File is not a zip file",
        "warnings": ["图结构提取失败：BadZipFile: File is not a zip file"],
        "cfg": {"nodes": [], "edges": []},
        "fcg": {"nodes": [], "edges": []},
        "api_graph": {"nodes": [], "edges": [], "api_call_counts": {}},
    }

    result = validator.validate(static_report, apk_ir, graph_data)

    assert result.anti_static_detected is True
    assert "抗静态检测" in result.adversarial_techniques
    assert result.robustness_score >= 10


def test_robustness_validator_treats_axml_warnings_as_parse_failure() -> None:
    """验证 AXML / namespace prefix 类报错也会被视为解析失败信号。"""

    validator = RobustnessValidator()
    apk_ir = APKIR(
        normalized_path="namespace-error.apk",
        file_name="namespace-error.apk",
        package_name="com.example.namespace",
    )
    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input="namespace-error.apk", status="ok", apk=apk_ir),
        risk_level="low",
        score=10,
        findings=[],
        expert_opinions={"主持人": "demo"},
        apk_summary={
            "graph_warnings": [
                "2026-06-24 22:18:20,570 [WARNING] androguard.axml: Name seems to contain a namespace prefix: 'http://schemas.android.com/apk/res/android'",
                "2026-06-24 22:18:20,570 [WARNING] androguard.axml: Name 'http://schemas.android.com/apk/res/android' contains invalid characters!",
            ]
        },
    )

    result = validator.validate(static_report, apk_ir, graph_data={})

    assert result.robustness_score >= 10
    assert result.anti_static_detected is True
    assert "抗静态检测" in result.adversarial_techniques


def test_robustness_validator_gains_bonus_when_graph_structure_missing() -> None:
    """验证只要图结构缺失，即使没有显式 fallback 标记也会加分。"""

    validator = RobustnessValidator()
    apk_ir = APKIR(
        normalized_path="missing-graph.apk",
        file_name="missing-graph.apk",
        package_name="com.example.missing",
    )
    static_report = DetectionReport(
        target_ir=TargetIR(target_type="apk", original_input="missing-graph.apk", status="ok", apk=apk_ir),
        risk_level="low",
        score=10,
        findings=[],
        expert_opinions={"主持人": "demo"},
        apk_summary={
            "graph_status": "图结构缺失",
            "graph_warnings": [],
        },
    )

    result = validator.validate(static_report, apk_ir, graph_data={})

    assert result.robustness_score >= 10
    assert result.anti_static_detected is True
    assert "抗静态检测" in result.adversarial_techniques


def test_scoring_integration() -> None:
    """测试综合评分是否包含仲裁与鲁棒性两个新维度。"""

    @dataclass
    class DummyArbitration:
        consistency_level: str = "low"

    @dataclass
    class DummyRobustness:
        robustness_score: float = 60.0

    evidence_score = 50
    deep_score = 50
    score_without_new_dims = combine_scores(evidence_score, deep_score)
    score_with_new_dims = combine_apk_scores(
        evidence_score,
        deep_score,
        DummyArbitration(),
        DummyRobustness(),
    )

    print("[scoring_integration]")
    print(f"combine_scores: {score_without_new_dims}")
    print(f"combine_apk_scores: {score_with_new_dims}")

    assert score_with_new_dims != score_without_new_dims


def _run_selected(test_name: str | None) -> None:
    tests = {
        "test_graph_extractor": test_graph_extractor,
        "test_graph_extractor_multi_dex_merge": test_graph_extractor_multi_dex_merge,
        "test_arbitrator": test_arbitrator,
        "test_robustness_validator": test_robustness_validator,
        "test_robustness_validator_detects_anti_static_analysis": test_robustness_validator_detects_anti_static_analysis,
        "test_apk_analyzer_marks_fallback_graph_on_bad_zip": test_apk_analyzer_marks_fallback_graph_on_bad_zip,
        "test_robustness_validator_gains_bonus_on_parse_fallback": test_robustness_validator_gains_bonus_on_parse_fallback,
        "test_scoring_integration": test_scoring_integration,
    }

    if test_name:
        if test_name not in tests:
            raise SystemExit(f"Unknown test: {test_name}. Available: {', '.join(tests)}")
        tests[test_name]()
        return

    for name, func in tests.items():
        print(f"\n=== Running {name} ===")
        func()


if __name__ == "__main__":
    selected = sys.argv[1] if len(sys.argv) > 1 else None
    _run_selected(selected)