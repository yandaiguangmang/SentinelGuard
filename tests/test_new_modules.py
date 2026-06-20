from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from SentinelGuard.analyzers.apk_graph_extractor import APKGraphExtractor
import SentinelGuard.analyzers.apk_graph_extractor as apk_graph_extractor_module
from SentinelGuard.arbitrator import Arbitrator
from SentinelGuard.robustness_validator import RobustnessValidator
from SentinelGuard.scoring import combine_apk_scores, combine_scores
from SentinelGuard.state import APKIR, DetectionFinding, DetectionReport, TargetIR


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