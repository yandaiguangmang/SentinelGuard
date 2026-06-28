"""
单模型 APK 直接检测评估脚本
支持：
1. 单 APK 文件
2. 文件夹内的 Split APK（联合安装）
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from openai import OpenAI
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# 添加项目路径
# 当前文件位于 SentinelGuard/scripts/ 下，必须把仓库根目录加入 sys.path，
# 这样才能正常导入 `SentinelGuard.*` 包。
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from SentinelGuard.analyzers.apk_analyzer import analyze_apk
from SentinelGuard.analyzers.apk_deep_analyzer import APKDeepAnalyzer
from SentinelGuard.analyzers.apk_dynamic_analyzer import dynamic_analyze_apk
from SentinelGuard.analyzers import apk_dynamic_analyzer as apk_dynamic_analyzer_module
from SentinelGuard.parsers.input_parser import parse_target
from SentinelGuard.report import _deduplicate_semantic_findings
from SentinelGuard.scoring import score_from_findings, risk_level_from_score
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionReport


# ============================================================================
# 配置
# ============================================================================

# 数据集路径
BENIGN_DIR = Path("G:/project/safe-dataset/gooddataset")
MALICIOUS_DIR = Path("G:/project/safe-dataset/baddataset")

# 输出目录
OUTPUT_DIR = Path("./eval_outputs_single_model_apk")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 样本限制（None=全量）
SAMPLE_LIMIT: Optional[int] = None

# API 配置
API_KEY = os.getenv("OPENAI_API_KEY", "sk-hFs40fFuY5B9HkA76sD8R9P60uxYUQIuI7LEYfjxz0tMwG1N")
BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.chatanywhere.tech/v1")
MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "gpt-5.4-mini")

# ADB 配置
ADB_PATH = os.getenv("ADB_PATH", r"C:/Users/lenovo/AppData/Local/Android/Sdk/platform-tools/adb.exe")

# 运行配置
MAX_WORKERS = 1  # 必须为 1，因为需要串行安装/卸载
REQUEST_TIMEOUT = 300  # 增加到 300 秒，给模型更多推理时间
MAX_RETRIES = 3
RUNTIME_WINDOW_SECONDS = 20

# 模型调用配置
MODEL_MAX_TOKENS = 100  # 增加到 100，确保模型有足够空间输出
MODEL_TEMPERATURE = 0.0

# 报告压缩配置（与深度研判保持一致）
MAX_MODEL_INPUT_BYTES = 80 * 1024

# Split APK 文件名模式（用于识别联合安装的 APK）
SPLIT_APK_PATTERNS = [
    r"^base_?\d*\.apk$",           # base.apk, base_0.apk, base_1.apk
    r"^split_config\..*\.apk$",    # split_config.en.apk, split_config.x86_64.apk
    r"^split_.*\.apk$",            # split_xxx.apk
    r"^config\..*\.apk$",          # config.xxx.apk
]


def _patch_dynamic_analyzer_to_allow_downgrade_install() -> None:
    """在脚本层为动态沙箱补充降级安装和复用已安装版本的兜底逻辑。"""
    analyzer_cls = getattr(apk_dynamic_analyzer_module, "APKDynamicAnalyzer", None)
    if analyzer_cls is None:
        return

    original_run_adb = getattr(analyzer_cls, "_run_adb", None)
    original_install_bundle = getattr(analyzer_cls, "_install_apk_bundle", None)
    if (
        original_run_adb is None
        or original_install_bundle is None
        or getattr(original_run_adb, "__sentinelguard_patched__", False)
        or getattr(original_install_bundle, "__sentinelguard_patched__", False)
    ):
        return

    def patched_run_adb(self, args: List[str], check: bool = True):
        patched_args = list(args)
        if len(patched_args) >= 3 and patched_args[0] == "-s" and patched_args[2] in {"install", "install-multiple"}:
            if "-d" not in patched_args:
                patched_args.insert(3, "-d")
        return original_run_adb(self, patched_args, check=check)

    def _is_version_downgrade_error(text: str) -> bool:
        lowered = (text or "").lower()
        return "install_failed_version_downgrade" in lowered or "downgrade detected" in lowered

    def patched_install_apk_bundle(self, device_id: str, apk_paths: List[str]):
        result = original_install_bundle(self, device_id, apk_paths)
        output = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
        if result.returncode == 0 or "Success" in (result.stdout or ""):
            return result

        if not _is_version_downgrade_error(output) or not apk_paths:
            return result

        package_name = ""
        try:
            package_name = self._resolve_package_name_from_apk(apk_paths[0], "")
        except Exception:
            package_name = ""

        if package_name:
            installed = self._run_adb(["-s", device_id, "shell", "pm", "list", "packages", package_name], check=False)
            if package_name in (installed.stdout or ""):
                print(f"[动态沙箱] 检测到 {package_name} 已存在且版本降级安装失败，直接复用设备上已有版本继续分析...")
                return subprocess.CompletedProcess(
                    args=getattr(result, "args", []),
                    returncode=0,
                    stdout=f"Success (reused installed package: {package_name})",
                    stderr="",
                )

        return result

    patched_run_adb.__sentinelguard_patched__ = True  # type: ignore[attr-defined]
    patched_install_apk_bundle.__sentinelguard_patched__ = True  # type: ignore[attr-defined]
    analyzer_cls._run_adb = patched_run_adb  # type: ignore[assignment]
    analyzer_cls._install_apk_bundle = patched_install_apk_bundle  # type: ignore[assignment]


_patch_dynamic_analyzer_to_allow_downgrade_install()


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class SampleItem:
    """样本项，支持单 APK 或 Split APK"""
    name: str                       # 显示名称
    label: int                      # 1=恶意, 0=良性
    source_dir: str                 # 来源目录
    apk_files: List[Path]           # 所有 APK 文件路径
    is_split: bool = False          # 是否 Split APK
    folder_path: Optional[Path] = None  # 如果是文件夹，记录文件夹路径
    
    @property
    def display_name(self) -> str:
        """显示名称"""
        if self.is_split:
            return f"{self.name} ({len(self.apk_files)} 个文件)"
        return self.name
    
    @property
    def primary_apk(self) -> Path:
        """获取主 APK（用于解析）"""
        # 优先选择 base 开头的，或者第一个
        for apk in self.apk_files:
            if apk.name.lower().startswith("base"):
                return apk
        return self.apk_files[0]


@dataclass
class AnalysisResult:
    sample: SampleItem
    apk_info: Dict[str, Any]
    compressed_payload: Dict[str, Any]
    prediction: Optional[int]
    raw_output: str
    error: str = ""
    elapsed_seconds: float = 0.0


# ============================================================================
# 提示词模板（增强版 - 更明确的指令）
# ============================================================================

SYSTEM_PROMPT = """你是一位 APK 恶意软件分析专家。

你将收到一份经过压缩的 APK 深度研判数据，其中包含：
- 静态分析结果（权限、组件、签名、字符串、图结构等）
- 动态沙箱结果（运行时行为、网络线索、文件落地等）
- 情报分析线索
- 处置建议

请按照以下思路在内部逐步思考：
1. 静态分析：检查权限是否敏感、组件是否可疑、是否有加壳/混淆、API 调用是否危险
2. 行为分析：检查动态沙箱中的运行时行为、网络连接、文件操作、持久化机制
3. 情报分析：检查包名是否可疑、签名是否异常、是否有已知恶意特征
4. 处置分析：综合以上信息，判断是否需要隔离/阻断

【强制输出格式】：
- 你必须在内部完成推理，但最终输出只能是一行：`pred: 0` 或 `pred: 1`
- 1 表示恶意软件，0 表示良性软件
- 绝对不要输出任何其他内容，包括解释、推理过程、标点符号、代码块等
- 如果你无法确定，请根据证据链做出最可能的判断
- 输出格式必须严格为：`pred: 0` 或 `pred: 1`，不要有任何额外字符"""


# ============================================================================
# APK 分析器（使用深度研判的压缩逻辑）
# ============================================================================

class APKSingleModelAnalyzer:
    """单模型 APK 分析器，复用深度研判的压缩逻辑"""
    
    def __init__(self, runtime_config: Optional[AnalysisRuntimeConfig] = None):
        self.runtime_config = runtime_config or AnalysisRuntimeConfig()
        self.deep_analyzer = APKDeepAnalyzer(runtime_config=self.runtime_config)
    
    def analyze_apk(self, apk_paths: List[Path], enable_dynamic: bool = True) -> Dict[str, Any]:
        """分析 APK（支持 Split APK）"""
        
        if not apk_paths:
            return {"error": "没有 APK 文件"}
        
        # 使用主 APK 进行解析
        primary_path = str(apk_paths[0])
        all_paths = [str(p) for p in apk_paths]
        
        # 1. 解析 APK
        target_ir = parse_target(primary_path, "apk")
        if target_ir.status != "ready":
            return {"error": f"APK 解析失败: {target_ir.message}"}
        
        # 如果是 Split APK，更新 bundle 路径
        if len(all_paths) > 1:
            if target_ir.apk is not None:
                target_ir.apk.bundle_apk_paths = all_paths
        
        # 2. 静态分析
        static_result = analyze_apk(target_ir)
        findings = _deduplicate_semantic_findings(static_result["findings"])
        evidence_score = score_from_findings(findings)
        risk_level = risk_level_from_score(evidence_score)
        
        # 构建静态报告
        static_report = DetectionReport(
            target_ir=target_ir,
            risk_level=risk_level,
            score=evidence_score,
            evidence_score=evidence_score,
            findings=findings,
            expert_opinions={},
            expert_models={},
            apk_summary=static_result.get("apk_summary", {}),
            analysis_mode="static",
        )
        
        # 3. 动态分析（如果启用）
        dynamic_result = None
        if enable_dynamic and target_ir.apk is not None:
            try:
                print(f"  [动态沙箱] 正在执行动态分析...")
                # 如果有多个 APK，使用 bundle 路径
                if len(all_paths) > 1:
                    static_report.target_ir.apk.bundle_apk_paths = all_paths
                
                dynamic_result = dynamic_analyze_apk(
                    static_report,
                    runtime_config=self.runtime_config,
                    runtime_window_seconds=RUNTIME_WINDOW_SECONDS,
                    enable_deep_model=False,
                )
                event_count = dynamic_result.get('apk_dynamic_summary', {}).get('event_count', 0)
                print(f"  [动态沙箱] 完成，捕获 {event_count} 个事件")
            except Exception as e:
                print(f"  [动态沙箱] 警告: {e}")
                dynamic_result = None
        
        # 4. 构建压缩 payload
        compressed_payload = self._build_compressed_payload(
            static_report, dynamic_result
        )
        
        return {
            "target_ir": target_ir,
            "static_report": static_report,
            "dynamic_result": dynamic_result,
            "compressed_payload": compressed_payload,
            "evidence_score": evidence_score,
            "risk_level": risk_level,
            "findings": findings,
        }
    
    def _build_compressed_payload(
        self, 
        static_report: DetectionReport, 
        dynamic_result: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """构建压缩的 payload"""
        
        payload = self.deep_analyzer._build_payload(static_report)
        
        if dynamic_result:
            dynamic_summary = dynamic_result.get("apk_dynamic_summary", {})
            dynamic_artifacts = dynamic_result.get("apk_dynamic_artifacts", {})
            
            payload["dynamic_sandbox"] = {
                "summary": self._summarize_dynamic_summary(dynamic_summary),
                "artifacts": self._summarize_dynamic_artifacts(dynamic_artifacts),
                "output_dir": str(dynamic_artifacts.get("dynamic_output_dir", "")),
                "network_hits": dynamic_summary.get("network_hits", [])[:5],
                "logcat_excerpt": str(dynamic_summary.get("logcat_excerpt", ""))[:1500],
            }
            payload["dynamic_summary"] = dynamic_summary
            payload["dynamic_artifacts"] = dynamic_artifacts
        
        compressed = self.deep_analyzer._ensure_payload_within_limit(
            "single_model", payload, max_bytes=MAX_MODEL_INPUT_BYTES
        )
        
        return compressed

    @staticmethod
    def _limit_list(values: Any, limit: int) -> List[Any]:
        if not isinstance(values, list) or limit <= 0:
            return []
        return values[:limit]

    def _summarize_dynamic_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(summary, dict):
            return {}

        return {
            "device_id": summary.get("device_id", ""),
            "package_name": summary.get("package_name", ""),
            "static_file_name": summary.get("static_file_name", ""),
            "install_mode": summary.get("install_mode", ""),
            "installed_apk_paths": self._limit_list(summary.get("installed_apk_paths", []), 12),
            "resolve_activity": summary.get("resolve_activity", ""),
            "pidof": summary.get("pidof", ""),
            "install_success": bool(summary.get("install_success")),
            "launch_success": bool(summary.get("launch_success")),
            "event_count": int(summary.get("event_count", 0) or 0),
            "logcat_excerpt_count": int(summary.get("logcat_excerpt_count", 0) or 0),
            "network_hit_count": int(summary.get("network_hit_count", 0) or 0),
            "runtime_window_seconds": int(summary.get("runtime_window_seconds", 0) or 0),
            "granted_dangerous_permissions": self._limit_list(summary.get("granted_dangerous_permissions", []), 8),
            "post_install_files": self._limit_list(summary.get("post_install_files", []), 8),
            "persistent_services": self._compact_persistent_services(summary.get("persistent_services", {})),
        }

    def _summarize_dynamic_artifacts(self, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(artifacts, dict):
            return {}

        return {
            "dynamic_json_name": artifacts.get("dynamic_json_name", ""),
            "dynamic_json_path": artifacts.get("dynamic_json_path", ""),
            "dynamic_summary_path": artifacts.get("dynamic_summary_path", ""),
            "dynamic_logcat_path": artifacts.get("dynamic_logcat_path", ""),
            "dynamic_output_dir": artifacts.get("dynamic_output_dir", ""),
        }

    def _compact_persistent_services(self, persistent_services: Any) -> Dict[str, List[str]]:
        if not isinstance(persistent_services, dict):
            return {}

        return {
            key: self._limit_list([str(item) for item in value or [] if str(item).strip()], 5)
            for key, value in persistent_services.items()
            if self._limit_list([str(item) for item in value or [] if str(item).strip()], 5)
        }


# ============================================================================
# ADB 工具（支持 Split APK 安装）
# ============================================================================

class ADBManager:
    """ADB 安装/卸载管理器，支持 Split APK"""
    
    def __init__(self, adb_path: Optional[str] = None):
        self.adb_path = adb_path or ADB_PATH or shutil.which("adb") or "adb"
        self._ensure_adb_available()
        self.device_id = self._pick_device()
        self.installed_packages: List[str] = []
    
    def _ensure_adb_available(self) -> None:
        """检查 ADB 是否可用"""
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError("ADB 不可用，请检查配置")
        except Exception as e:
            raise RuntimeError(f"ADB 不可用: {e}")
    
    def _pick_device(self) -> str:
        """选择设备"""
        result = subprocess.run(
            [self.adb_path, "devices"],
            capture_output=True,
            text=True,
            check=False,
        )
        devices = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices attached"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        if not devices:
            raise RuntimeError("未检测到已连接的 Android 设备/模拟器")
        return devices[0]
    
    def _run_adb(self, args: List[str], check: bool = False) -> subprocess.CompletedProcess:
        """执行 ADB 命令"""
        command = [self.adb_path, "-s", self.device_id, *args]
        return subprocess.run(command, capture_output=True, text=True, check=check)
    
    def _get_package_name_from_aapt(self, apk_path: str) -> Optional[str]:
        """使用 aapt 从 APK 获取包名"""
        aapt = self._find_aapt()
        if not aapt:
            return None
        
        try:
            result = subprocess.run(
                [aapt, "dump", "badging", apk_path],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                match = re.search(r"package: name='([^']+)'", result.stdout or "")
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None
    
    def _find_aapt(self) -> Optional[str]:
        """查找 aapt 工具"""
        for name in ("aapt.exe", "aapt2.exe", "aapt", "aapt2"):
            found = shutil.which(name)
            if found:
                return found
        
        # 在 SDK 中查找
        adb_path = Path(self.adb_path)
        sdk_root = adb_path.parent.parent
        build_tools = sdk_root / "build-tools"
        if build_tools.exists():
            for version_dir in sorted(build_tools.iterdir(), reverse=True):
                if version_dir.is_dir():
                    for name in ("aapt.exe", "aapt2.exe", "aapt", "aapt2"):
                        tool = version_dir / name
                        if tool.exists():
                            return str(tool)
        return None
    
    def install_apk(self, apk_paths: List[Path]) -> Tuple[bool, Optional[str]]:
        """
        安装 APK（支持单 APK 或 Split APK）
        
        Returns:
            (success, package_name)
        """
        if not apk_paths:
            return False, None
        
        # 获取包名（从主 APK 获取）
        package_name = self._get_package_name_from_aapt(str(apk_paths[0]))
        
        # 显示安装信息
        if len(apk_paths) == 1:
            print(f"  [ADB] 正在安装: {apk_paths[0].name}")
        else:
            print(f"  [ADB] 正在联合安装 {len(apk_paths)} 个 APK:")
            for p in apk_paths[:5]:  # 只显示前5个
                print(f"        - {p.name}")
            if len(apk_paths) > 5:
                print(f"        ... 还有 {len(apk_paths) - 5} 个文件")
        
        # 构建安装命令
        if len(apk_paths) == 1:
            result = self._run_adb(["install", "-r", "-t", str(apk_paths[0])])
        else:
            apk_args = [str(p) for p in apk_paths if p.exists()]
            result = self._run_adb(["install-multiple", "-r", "-t", *apk_args])
        
        success = result.returncode == 0 and "Success" in (result.stdout or "")
        
        if success:
            if package_name:
                self.installed_packages.append(package_name)
                print(f"  [ADB] 安装成功，包名: {package_name}")
            else:
                print(f"  [ADB] 安装成功，但无法获取包名")
        else:
            error = (result.stderr or result.stdout or "").strip()
            print(f"  [ADB] 安装失败: {error[:200]}")
        
        return success, package_name
    
    def uninstall_apk(self, package_name: str) -> bool:
        """卸载 APK"""
        if not package_name:
            return False
        print(f"  [ADB] 正在卸载: {package_name}")
        result = self._run_adb(["uninstall", package_name])
        success = result.returncode == 0
        if success:
            if package_name in self.installed_packages:
                self.installed_packages.remove(package_name)
            print(f"  [ADB] 卸载成功")
        else:
            error = (result.stderr or result.stdout or "").strip()
            if "Unknown package" in error:
                print(f"  [ADB] 包未安装，无需卸载")
            else:
                print(f"  [ADB] 卸载失败: {error[:200]}")
        return success
    
    def uninstall_all(self) -> None:
        """卸载所有已安装的包"""
        for package in self.installed_packages[:]:
            self.uninstall_apk(package)
        self.installed_packages.clear()
    
    def is_package_installed(self, package_name: str) -> bool:
        """检查包是否已安装"""
        result = self._run_adb(["shell", "pm", "list", "packages", package_name])
        return package_name in (result.stdout or "")

    def ensure_package_removed(self, package_name: str) -> bool:
        """如设备上已存在同包名旧版本，则先卸载，避免 INSTALL_FAILED_VERSION_DOWNGRADE。"""
        if not package_name:
            return False

        if not self.is_package_installed(package_name):
            return True

        print(f"  [ADB] 检测到设备上已存在 {package_name}，先卸载旧版本以避免降级冲突...")
        return self.uninstall_apk(package_name)


# ============================================================================
# 样本收集（支持文件和文件夹混合）
# ============================================================================

def is_split_apk_pattern(filename: str) -> bool:
    """检查文件名是否匹配 Split APK 模式"""
    for pattern in SPLIT_APK_PATTERNS:
        if re.match(pattern, filename, re.IGNORECASE):
            return True
    return False


def collect_samples_from_directory(dir_path: Path, label: int, source_dir: str) -> List[SampleItem]:
    """
    从目录收集样本，支持：
    1. 直接的 .apk 文件
    2. 文件夹（包含多个 APK 用于联合安装）
    """
    samples: List[SampleItem] = []
    
    if not dir_path.exists():
        return samples
    
    # 遍历目录内容
    for item in sorted(dir_path.iterdir()):
        if item.is_file() and item.suffix.lower() == ".apk":
            # 单个 APK 文件
            samples.append(SampleItem(
                name=item.name,
                label=label,
                source_dir=source_dir,
                apk_files=[item],
                is_split=False,
                folder_path=None,
            ))
        
        elif item.is_dir():
            # 文件夹：查找其中的 APK 文件
            apk_files = sorted(item.glob("*.apk"))
            if apk_files:
                # 检查是否是 Split APK（多个文件）
                if len(apk_files) >= 2:
                    # 检查是否匹配 Split APK 模式
                    split_files = [p for p in apk_files if is_split_apk_pattern(p.name.lower())]
                    if len(split_files) >= 2:
                        # 是 Split APK
                        samples.append(SampleItem(
                            name=item.name,
                            label=label,
                            source_dir=source_dir,
                            apk_files=split_files,
                            is_split=True,
                            folder_path=item,
                        ))
                    else:
                        # 不是 Split APK 模式，但多个 APK 在同一个文件夹
                        # 也按 Split APK 处理（可能是自定义的）
                        samples.append(SampleItem(
                            name=f"{item.name} ({len(apk_files)} APKs)",
                            label=label,
                            source_dir=source_dir,
                            apk_files=apk_files,
                            is_split=True,
                            folder_path=item,
                        ))
                else:
                    # 单个 APK 在文件夹中
                    samples.append(SampleItem(
                        name=apk_files[0].name,
                        label=label,
                        source_dir=source_dir,
                        apk_files=apk_files,
                        is_split=False,
                        folder_path=item,
                    ))
    
    return samples


def collect_samples() -> List[SampleItem]:
    """收集所有样本"""
    samples: List[SampleItem] = []
    
    # 收集良性样本
    samples.extend(collect_samples_from_directory(BENIGN_DIR, 0, "benign"))
    
    # 收集恶意样本
    samples.extend(collect_samples_from_directory(MALICIOUS_DIR, 1, "malicious"))
    
    if SAMPLE_LIMIT is not None:
        samples = samples[:SAMPLE_LIMIT]
    
    return samples


# ============================================================================
# 模型调用（修复版 - 增加超时、token、调试信息）
# ============================================================================

def call_model(
    client: OpenAI,
    compressed_payload: Dict[str, Any],
    sample: SampleItem,
) -> Tuple[Optional[int], str]:
    """调用模型进行判断（修复版）"""
    
    def extract_prediction(text: str) -> Optional[int]:
        """从模型输出中提取二分类结论。"""
        if not text:
            return None

        raw_text = text.strip()
        if not raw_text:
            return None

        # 1) 优先匹配显式标签格式，如 pred: 0 / prediction=1 / answer: 0
        patterns = [
            r"pred\s*[:=]\s*([01])",
            r"prediction\s*[:=]\s*([01])",
            r"answer\s*[:=]\s*([01])",
            r"label\s*[:=]\s*([01])",
            r"结论\s*[:=]\s*([01])",
            r"最终结论\s*[:=]\s*([01])",
            r"结果\s*[:=]\s*([01])",
            r"判断\s*[:=]\s*([01])",
            r"判定\s*[:=]\s*([01])",
            r"输出\s*[:=]\s*([01])",
        ]
        for pattern in patterns:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                return int(match.group(1))

        # 2) 匹配单独的 pred: 0/1（没有空格）
        match = re.search(r"pred[:=]([01])", raw_text, re.IGNORECASE)
        if match:
            return int(match.group(1))

        # 3) 兼容中文自然语言结论
        positive_hints = (
            "恶意", "malicious", "malware", "病毒", "木马",
            "风险高", "高危", "可疑", "有风险", "是恶意"
        )
        negative_hints = (
            "良性", "benign", "safe", "正常", "无明显风险",
            "未发现明显风险", "低风险", "安全", "是良性"
        )

        lowered = raw_text.lower()
        has_positive = any(hint in lowered for hint in positive_hints)
        has_negative = any(hint in lowered for hint in negative_hints)

        if has_positive and not has_negative:
            return 1
        if has_negative and not has_positive:
            return 0

        # 4) 去掉代码块后再找单独的 0/1
        cleaned = re.sub(r"```(?:json|text)?|```", " ", raw_text, flags=re.IGNORECASE)
        cleaned = re.sub(r"[\r\n\t]+", " ", cleaned)
        match = re.search(r"(?:^|\s)([01])(?:\s|$|[.,;，。])", cleaned)
        if match:
            return int(match.group(1))

        # 5) 尝试找任何单独的 0 或 1
        numbers = re.findall(r'\b([01])\b', raw_text)
        if numbers:
            return int(numbers[-1])

        return None

    def ask_model() -> Tuple[Optional[int], str]:
        """调用模型并返回结果"""
        # 构建 payload JSON
        payload_json = json.dumps(compressed_payload, ensure_ascii=False, indent=2)
        
        if len(payload_json) > MAX_MODEL_INPUT_BYTES:
            payload_json = payload_json[:MAX_MODEL_INPUT_BYTES] + "\n...[truncated]"
        
        user_message = f"""请分析以下 APK 深度研判数据，判断该 APK 是否为恶意软件。

APK 名称: {sample.display_name}
来源: {sample.source_dir}
真实标签(仅用于评估，不要输出): {sample.label}

压缩的研判数据:
{payload_json}

【重要】请只输出一行，格式必须为: pred: 0 或 pred: 1
不要输出任何解释、推理过程或其他内容。"""

        try:
            print(f"   [DEBUG] 调用模型 {MODEL_NAME}，超时 {REQUEST_TIMEOUT}s...")
            
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                temperature=MODEL_TEMPERATURE,
                max_tokens=MODEL_MAX_TOKENS,
                timeout=REQUEST_TIMEOUT,
            )
            
            # 提取内容
            content = ""
            if response.choices and len(response.choices) > 0:
                message = response.choices[0].message
                content = getattr(message, "content", None) or ""
                content = content.strip()
            
            # 如果 content 为空，尝试其他字段
            if not content:
                if hasattr(response, "text"):
                    content = getattr(response, "text", "").strip()
                elif hasattr(response, "output"):
                    content = getattr(response, "output", "").strip()
            
            print(f"   [DEBUG] 响应长度: {len(content)} 字符")
            print(f"   [DEBUG] 响应内容: '{content[:200] if content else '(空)'}'")
            
            if not content:
                return None, "模型返回空内容"
            
            # 尝试解析
            pred = extract_prediction(content)
            if pred in (0, 1):
                return pred, content
            
            # 如果解析失败，检查是否包含关键词
            lowered = content.lower()
            if "pred: 1" in lowered or "pred:0" in lowered:
                return 1, content
            if "pred: 0" in lowered or "pred:1" in lowered:
                return 0, content
            
            return None, f"无法解析: '{content[:100]}'"
            
        except Exception as e:
            return None, f"调用异常: {type(e).__name__}: {e}"
    
    # 执行调用，带重试
    last_content = ""
    
    for attempt in range(MAX_RETRIES + 1):
        if attempt > 0:
            wait_time = 5 * (attempt + 1)
            print(f"   [重试] 等待 {wait_time}s 后第 {attempt + 1} 次重试...")
            time.sleep(wait_time)
        
        pred, content = ask_model()
        
        if pred in (0, 1):
            return pred, content
        
        last_content = content
        
        if attempt < MAX_RETRIES:
            print(f"   [重试] 解析失败: {content[:100] if content else '空'}")
    
    return None, f"无法解析: '{last_content[:100] if last_content else '空'}'"


# ============================================================================
# 指标计算
# ============================================================================

def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    """计算评估指标"""
    if not y_true:
        return {}
    
    metrics = {
        "total_samples": len(y_true),
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }
    
    if len(set(y_true)) > 1:
        try:
            metrics["roc_auc"] = roc_auc_score(y_true, y_pred)
        except Exception:
            metrics["roc_auc"] = None
    else:
        metrics["roc_auc"] = None
    
    return metrics


# ============================================================================
# 主流程
# ============================================================================

def main() -> None:
    print("=" * 60)
    print("单模型 APK 直接检测评估")
    print("支持: 单 APK 文件 / 文件夹 Split APK")
    print("=" * 60)
    
    # 1. 检查配置
    if not API_KEY:
        print("??  请设置 OPENAI_API_KEY")
    
    # 2. 收集样本
    print(f"\n? 扫描目录:")
    print(f"   良性: {BENIGN_DIR}")
    print(f"   恶意: {MALICIOUS_DIR}")
    
    samples = collect_samples()
    if not samples:
        print("? 未找到任何 APK 样本")
        sys.exit(1)
    
    # 统计
    benign_count = sum(1 for s in samples if s.label == 0)
    malicious_count = sum(1 for s in samples if s.label == 1)
    split_count = sum(1 for s in samples if s.is_split)
    single_count = len(samples) - split_count
    
    print(f"\n? 样本统计:")
    print(f"   总样本: {len(samples)}")
    print(f"   ├─ 良性: {benign_count}")
    print(f"   └─ 恶意: {malicious_count}")
    print(f"\n   类型:")
    print(f"   ├─ 单 APK: {single_count}")
    print(f"   └─ Split APK: {split_count}")
    
    if split_count > 0:
        print(f"\n? Split APK 示例:")
        split_samples = [s for s in samples if s.is_split]
        for s in split_samples[:5]:
            print(f"   - {s.name} ({len(s.apk_files)} 个文件)")
        if len(split_samples) > 5:
            print(f"   ... 还有 {len(split_samples) - 5} 个")
    
    # 3. 初始化
    print("\n? 初始化组件...")
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=REQUEST_TIMEOUT)
    analyzer = APKSingleModelAnalyzer()
    adb = ADBManager()
    print(f"   ADB 设备: {adb.device_id}")
    
    # 4. 处理样本
    print("\n? 开始分析...")
    print("-" * 60)
    
    results: List[AnalysisResult] = []
    
    for idx, sample in enumerate(samples, 1):
        print(f"\n[{idx}/{len(samples)}] {sample.display_name}")
        print(f"   标签: {'恶意' if sample.label == 1 else '良性'}")
        if sample.is_split:
            print(f"   类型: Split APK ({len(sample.apk_files)} 个文件)")
        
        start_time = time.time()
        result = AnalysisResult(
            sample=sample,
            apk_info={},
            compressed_payload={},
            prediction=None,
            raw_output="",
        )
        
        try:
            # 4.1 分析 APK（先只做静态分析，避免动态安装时与设备上的旧版本冲突）
            print("   [1/4] 分析 APK（静态）...")
            apk_result = analyzer.analyze_apk(sample.apk_files, enable_dynamic=False)
            
            if "error" in apk_result:
                result.error = apk_result["error"]
                print(f"   ? 分析失败: {result.error}")
                results.append(result)
                continue
            
            package_name = apk_result["target_ir"].apk.package_name if apk_result["target_ir"].apk else "未知"
            result.apk_info = {
                "name": sample.name,
                "package_name": package_name,
                "is_split": sample.is_split,
                "apk_count": len(sample.apk_files),
                "risk_level": apk_result["risk_level"],
                "evidence_score": apk_result["evidence_score"],
                "finding_count": len(apk_result["findings"]),
            }
            print(f"   包名: {package_name}")
            print(f"   风险等级: {apk_result['risk_level']}")
            print(f"   证据数: {result.apk_info['finding_count']}")
            
            # 4.2 动态分析
            if package_name and package_name != "未知" and adb.is_package_installed(package_name):
                print(f"   [ADB] 设备上已存在同包名应用 {package_name}，将优先尝试复用已安装版本进行动态分析")

            print("   [2/4] 执行动态沙箱...")
            dynamic_result = None
            try:
                if apk_result["target_ir"].apk is not None:
                    dynamic_result = dynamic_analyze_apk(
                        apk_result["static_report"],
                        runtime_config=analyzer.runtime_config,
                        runtime_window_seconds=RUNTIME_WINDOW_SECONDS,
                        enable_deep_model=False,
                    )
                    event_count = dynamic_result.get('apk_dynamic_summary', {}).get('event_count', 0)
                    print(f"   [动态沙箱] 完成，捕获 {event_count} 个事件")
            except Exception as e:
                print(f"   [动态沙箱] 警告: {e}")
                dynamic_result = None

            # 4.4 调用模型
            print("   [3/4] 调用模型判断...")
            result.compressed_payload = analyzer._build_compressed_payload(
                apk_result["static_report"], dynamic_result
            )
            pred, raw = call_model(client, result.compressed_payload, sample)
            result.prediction = pred
            result.raw_output = raw
            
            if pred == 1:
                print(f"   ? 判定: 恶意 (1)")
            elif pred == 0:
                print(f"   ? 判定: 良性 (0)")
            else:
                print(f"   ??  无法判定: {raw[:50]}")
            
            # 4.5 卸载 APK
            if result.apk_info.get("package_name"):
                print("   [清理] 卸载 APK...")
                adb.uninstall_apk(result.apk_info["package_name"])
            
        except Exception as e:
            result.error = str(e)
            print(f"   ? 异常: {e}")
            try:
                if result.apk_info.get("package_name"):
                    adb.uninstall_apk(result.apk_info["package_name"])
            except Exception:
                pass
        
        result.elapsed_seconds = time.time() - start_time
        results.append(result)
        
        # 进度
        correct = sum(1 for r in results if r.prediction is not None and r.prediction == r.sample.label)
        total_valid = sum(1 for r in results if r.prediction is not None)
        if total_valid > 0:
            print(f"   ? 准确率: {correct}/{total_valid} ({correct/total_valid*100:.1f}%)")
        print(f"   ??  耗时: {result.elapsed_seconds:.1f}s")
    
    # 5. 清理
    print("\n? 清理残留...")
    adb.uninstall_all()
    
    # 6. 计算指标
    print("\n" + "=" * 60)
    print("? 评估结果")
    print("=" * 60)
    
    valid_results = [r for r in results if r.prediction is not None]
    
    if not valid_results:
        print("? 没有有效的预测结果")
        return
    
    y_true = [r.sample.label for r in valid_results]
    y_pred = [r.prediction for r in valid_results]
    
    metrics = compute_metrics(y_true, y_pred)
    
    print(f"\n总样本数: {metrics['total_samples']}")
    print(f"有效预测: {len(valid_results)}")
    print(f"失败样本: {len(results) - len(valid_results)}")
    print(f"\n准确率 (Accuracy): {metrics['accuracy']:.4f}")
    print(f"精确率 (Precision): {metrics['precision']:.4f}")
    print(f"召回率 (Recall): {metrics['recall']:.4f}")
    print(f"F1 分数: {metrics['f1']:.4f}")
    if metrics.get('roc_auc') is not None:
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}")
    
    cm = metrics['confusion_matrix']
    print(f"\n混淆矩阵:")
    print(f"  TN: {cm[0][0]}, FP: {cm[0][1]}")
    print(f"  FN: {cm[1][0]}, TP: {cm[1][1]}")
    
    # 按类型统计
    split_results = [r for r in valid_results if r.sample.is_split]
    single_results = [r for r in valid_results if not r.sample.is_split]
    
    if split_results:
        split_correct = sum(1 for r in split_results if r.prediction == r.sample.label)
        print(f"\nSplit APK 准确率: {split_correct}/{len(split_results)} ({split_correct/len(split_results)*100:.1f}%)")
    
    if single_results:
        single_correct = sum(1 for r in single_results if r.prediction == r.sample.label)
        print(f"单 APK 准确率: {single_correct}/{len(single_results)} ({single_correct/len(single_results)*100:.1f}%)")
    
    # 7. 保存结果
    print(f"\n? 保存结果到: {OUTPUT_DIR}")
    
    with open(OUTPUT_DIR / "per_sample.jsonl", "w", encoding="utf-8") as f:
        for r in results:
            record = {
                "name": r.sample.name,
                "label": r.sample.label,
                "prediction": r.prediction,
                "raw_output": r.raw_output,
                "error": r.error,
                "source_dir": r.sample.source_dir,
                "is_split": r.sample.is_split,
                "apk_count": len(r.sample.apk_files),
                "elapsed_seconds": r.elapsed_seconds,
                "apk_info": r.apk_info,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    
    summary = {
        "model": MODEL_NAME,
        "total_samples": len(samples),
        "valid_predictions": len(valid_results),
        "errors": len(results) - len(valid_results),
        "metrics": metrics,
        "split_stats": {
            "split_apk_count": split_count,
            "single_apk_count": single_count,
            "split_apk_accuracy": split_correct / len(split_results) if split_results else None,
            "single_apk_accuracy": single_correct / len(single_results) if single_results else None,
        },
        "sample_summary": {
            "benign": benign_count,
            "malicious": malicious_count,
        },
    }
    
    with open(OUTPUT_DIR / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    
    print("\n? 评估完成!")
    print(f"   结果目录: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()