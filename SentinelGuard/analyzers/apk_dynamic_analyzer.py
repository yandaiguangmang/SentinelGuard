from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config import settings
from SentinelGuard.analyzers.apk_deep_analyzer import APKDeepAnalyzer
from SentinelGuard.report import _deduplicate_semantic_findings
from SentinelGuard.scoring import combine_apk_scores, risk_level_from_score, score_from_findings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport


@dataclass
class ApkDynamicRuntimeResult:
    findings: List[DetectionFinding]
    apk_dynamic_summary: Dict[str, Any]
    apk_dynamic_artifacts: Dict[str, Any]
    expert_opinions: Dict[str, str]
    expert_models: Dict[str, str]
    deep_summary: str


class ApkDynamicAnalyzerError(RuntimeError):
    pass


class APKDynamicModelAnalyzer(APKDeepAnalyzer):
    def __init__(self, runtime_config: AnalysisRuntimeConfig | None, dynamic_context: Dict[str, Any]) -> None:
        self.dynamic_context = dynamic_context
        super().__init__(runtime_config=runtime_config)

    def _build_payload(self, static_report: DetectionReport) -> Dict[str, Any]:
        payload = super()._build_payload(static_report)
        payload["dynamic_sandbox"] = self.dynamic_context
        payload["analysis_instruction"] = "请以 dynamic_sandbox 中整理后的沙盒线索为主要依据进行五角色协同研判，additional_findings 必须来自这些动态线索，不要仅复述静态规则。"
        return payload

    def _build_role_payload(self, role: str, static_report: DetectionReport, base_payload: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._build_role_payload(role, static_report, base_payload)
        if role in {"静态分析员", "行为分析员", "情报分析员", "处置建议员"}:
            payload["dynamic_sandbox"] = self.dynamic_context
            payload["dynamic_summary"] = self.dynamic_context.get("dynamic_summary", {})
            payload["dynamic_artifacts"] = self.dynamic_context.get("dynamic_artifacts", {})
            payload["dynamic_output_dir"] = self.dynamic_context.get("dynamic_output_dir", "")
            payload["analysis_instruction"] = "请结合 dynamic_sandbox 中的动态沙箱证据输出对应角色结论，不要忽略运行时线索。"
        return payload

    def _build_host_payload(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        # 主持人只接收前四个角色的输出，避免把动态沙箱明细再次塞回去导致输入膨胀。
        return super()._build_host_payload(static_report, role_outputs)

    @staticmethod
    def _role_stage(role: str) -> str:
        return {
            "静态分析员": "dynamic_model_static",
            "行为分析员": "dynamic_model_behavior",
            "情报分析员": "dynamic_model_intel",
            "处置建议员": "dynamic_model_advice",
            "主持人": "dynamic_model_host",
        }.get(role, "dynamic_model_analysis")

    @staticmethod
    def _role_progress(role: str) -> int:
        return {
            "静态分析员": 80,
            "行为分析员": 84,
            "情报分析员": 88,
            "处置建议员": 92,
            "主持人": 95,
        }.get(role, 80)


class APKDynamicAnalyzer:
    SUSPICIOUS_PERMISSION_KEYWORDS = (
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
        "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
        "QUERY_ALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE",
    )

    def __init__(self, adb_path: str | None = None, runtime_window_seconds: int | None = None, runtime_config: AnalysisRuntimeConfig | None = None) -> None:
        self.adb_path = adb_path or settings.ADB_PATH or shutil.which("adb") or "adb"
        self.runtime_window_seconds = int(runtime_window_seconds or settings.APK_DYNAMIC_RUNTIME_WINDOW_SECONDS)
        self.runtime_config = runtime_config or AnalysisRuntimeConfig()

    def analyze(self, static_report: DetectionReport, progress_callback=None) -> Dict[str, Any]:
        apk_ir = static_report.target_ir.apk
        if not apk_ir:
            raise ApkDynamicAnalyzerError("缺少 APK 预检信息，无法执行动态分析。")

        package_name = self._resolve_package_name_from_apk(apk_ir.normalized_path, apk_ir.package_name.strip())

        if progress_callback:
            progress_callback("dynamic_prepare", "正在准备 APK 动态沙箱", 70)

        self._ensure_adb_available()
        device_id = self._pick_device()

        if progress_callback:
            progress_callback("dynamic_install", "正在安装 APK 到模拟器", 76)
        self._run_adb(["-s", device_id, "logcat", "-c"], check=False)
        self._run_adb(["-s", device_id, "shell", "logcat", "-c"], check=False)
        install_result = self._run_adb(["-s", device_id, "install", "-r", apk_ir.normalized_path], check=False)

        events: List[Dict[str, Any]] = []
        events.append(self._event("install", "adb", install_result.returncode, install_result.stdout, install_result.stderr))
        if install_result.returncode != 0 and "Success" not in (install_result.stdout or ""):
            raise ApkDynamicAnalyzerError(f"APK 安装失败：{(install_result.stderr or install_result.stdout or '').strip()}")

        if not package_name:
            package_name = self._resolve_installed_package_name(device_id, apk_ir.normalized_path, apk_ir.file_name)
        if not package_name:
            raise ApkDynamicAnalyzerError(
                "APK 未解析到包名，且安装后仍无法识别包名。请检查 APK 的 manifest 是否完整，或确认样本不是被损坏/加壳导致的特殊包。"
            )

        if progress_callback:
            progress_callback("dynamic_prepare", "正在收集设备与包信息", 72)
        package_info = self._collect_package_info(device_id, package_name)

        if progress_callback:
            progress_callback("dynamic_launch", "正在启动应用并采集运行时日志", 82)
        launch_result = self._launch_package(device_id, package_name)
        events.append(self._event("launch", "adb", launch_result.returncode, launch_result.stdout, launch_result.stderr))

        if progress_callback:
            progress_callback("dynamic_collect", "正在采集 logcat、权限、文件与持久化线索", 87)
        logcat_output = self._capture_logcat(device_id)
        events.extend(self._extract_events_from_logcat(logcat_output, package_name))

        package_info = self._collect_package_info(device_id, package_name)
        granted_permissions = self._extract_granted_permissions(package_info.get("dumpsys_excerpt", ""))
        dropped_files = self._collect_suspicious_files(device_id, package_name)
        persistent_services = self._collect_persistent_services(device_id, package_name)
        network_hits = self._extract_network_hits(logcat_output)

        if network_hits:
            events.append(self._event("network_hits", "logcat", 0, "; ".join(network_hits), ""))
        if granted_permissions:
            events.append(self._event("granted_permissions", "dumpsys", 0, "; ".join(granted_permissions), ""))
        if dropped_files:
            events.append(self._event("post_install_files", "adb", 1, "; ".join(dropped_files), ""))
        if persistent_services:
            events.append(self._event("persistent_services", "dumpsys", 2, json.dumps(persistent_services, ensure_ascii=False), ""))
        if package_info.get("resolve_activity"):
            events.append(self._event("resolve_activity", "dumpsys", 0, package_info.get("resolve_activity", ""), ""))
        if package_info.get("pidof"):
            events.append(self._event("pidof", "dumpsys", 0, package_info.get("pidof", ""), ""))

        if progress_callback:
            progress_callback("dynamic_evidence", "正在整理动态证据并抓取截图", 92)
        artifacts = self._write_dynamic_artifacts(
            static_report,
            device_id,
            package_name,
            package_info,
            granted_permissions,
            dropped_files,
            persistent_services,
            events,
            logcat_output,
        )
        summary = self._build_summary(
            static_report,
            device_id,
            package_name,
            package_info,
            granted_permissions,
            dropped_files,
            persistent_services,
            events,
            logcat_output,
            install_result,
            launch_result,
        )
        dynamic_context = self._build_dynamic_context(static_report, summary, artifacts, events, logcat_output)
        model_result = self._analyze_dynamic_context(static_report, dynamic_context, progress_callback=progress_callback)
        sandbox_findings = self._build_findings(
            package_name,
            events,
            logcat_output,
            granted_permissions,
            dropped_files,
            persistent_services,
        )
        model_findings = model_result.get("additional_findings", [])
        merged_findings = _deduplicate_semantic_findings([*sandbox_findings, *model_findings])

        if progress_callback:
            progress_callback("dynamic_done", "APK 动态沙箱分析已完成", 96)

        return {
            "findings": merged_findings,
            "apk_dynamic_summary": summary,
            "apk_dynamic_artifacts": artifacts,
            "expert_opinions": model_result.get("expert_opinions", {}),
            "expert_models": model_result.get("expert_models", {}),
            "deep_summary": model_result.get("deep_summary", ""),
            "arbitration_result": model_result.get("arbitration_result"),
            "robustness_result": model_result.get("robustness_result"),
            "risk_level": model_result.get("risk_level", risk_level_from_score(combine_apk_scores(
                score_from_findings(merged_findings),
                model_result.get("deep_score"),
                model_result.get("arbitration_result"),
                model_result.get("robustness_result"),
            ))),
            "score": combine_apk_scores(
                score_from_findings(merged_findings),
                model_result.get("deep_score"),
                model_result.get("arbitration_result"),
                model_result.get("robustness_result"),
            ),
            "evidence_score": score_from_findings(merged_findings),
            "deep_score": model_result.get("deep_score"),
        }

    def _ensure_adb_available(self) -> None:
        if not self.adb_path:
            raise ApkDynamicAnalyzerError("未找到 adb，请确认 Android Studio 平台工具已安装并加入 PATH。")
        result = self._run_adb(["version"], check=False)
        if result.returncode != 0:
            raise ApkDynamicAnalyzerError("adb 不可用，请检查 Android Studio 平台工具或 ADB_PATH 配置。")

    def _pick_device(self) -> str:
        result = self._run_adb(["devices"], check=False)
        if result.returncode != 0:
            raise ApkDynamicAnalyzerError((result.stderr or result.stdout or "无法枚举设备").strip())

        devices: List[str] = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices attached"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        if not devices:
            raise ApkDynamicAnalyzerError("未检测到已连接的 Android 模拟器。")
        return devices[0]

    def _launch_package(self, device_id: str, package_name: str) -> subprocess.CompletedProcess[str]:
        return self._run_adb([
            "-s", device_id, "shell", "monkey", "-p", package_name,
            "-c", "android.intent.category.LAUNCHER", "1",
        ], check=False)

    def _capture_logcat(self, device_id: str) -> str:
        process = subprocess.Popen(
            [self.adb_path, "-s", device_id, "logcat", "-d", "-v", "time"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        try:
            stdout, stderr = process.communicate(timeout=self.runtime_window_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        return stdout or stderr or ""

    def _capture_ui_screenshot(self, device_id: str, ui_trace_dir: Path, package_name: str, label: str) -> str:
        ui_trace_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        safe_package_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", package_name or "unknown.package").strip("._-") or "unknown.package"
        screenshot_path = ui_trace_dir / f"{safe_package_name}_{label}_{timestamp}.png"

        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "exec-out", "screencap", "-p"],
                capture_output=True,
                check=False,
            )
        except Exception:
            return ""

        if result.returncode != 0 or not result.stdout:
            return ""

        raw_bytes = bytes(result.stdout)
        if raw_bytes:
            screenshot_path.write_bytes(raw_bytes)
            return str(screenshot_path.as_posix())
        return ""

    def _resolve_package_name_from_apk(self, apk_path: str, fallback: str = "") -> str:
        candidate = (fallback or "").strip()
        if candidate:
            return candidate

        aapt = self._find_aapt_tool()
        if not aapt:
            return ""

        try:
            result = subprocess.run(
                [aapt, "dump", "badging", apk_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
        except Exception:
            return ""

        if result.returncode != 0:
            return ""

        match = re.search(r"package: name='([^']+)'", result.stdout or "")
        return match.group(1).strip() if match else ""

    def _find_aapt_tool(self) -> str:
        for tool_name in ("aapt.exe", "aapt2.exe", "aapt", "aapt2"):
            found = shutil.which(tool_name)
            if found:
                return found

        adb_path = Path(self.adb_path)
        sdk_root = adb_path.parent.parent if adb_path.name.lower() == "adb.exe" else adb_path.parent
        build_tools_dir = sdk_root / "build-tools"
        if not build_tools_dir.exists():
            return ""

        candidates: List[Path] = []
        for version_dir in sorted(build_tools_dir.iterdir(), reverse=True):
            if not version_dir.is_dir():
                continue
            for tool_name in ("aapt.exe", "aapt2.exe", "aapt", "aapt2"):
                tool_path = version_dir / tool_name
                if tool_path.exists():
                    candidates.append(tool_path)
                    break
            if candidates:
                break

        return str(candidates[0]) if candidates else ""

    def _resolve_installed_package_name(self, device_id: str, apk_path: str, file_name: str) -> str:
        apk_name = Path(apk_path).name or file_name
        package_listing = self._run_adb(["-s", device_id, "shell", "pm", "list", "packages", "-f"], check=False)
        lines = (package_listing.stdout or package_listing.stderr or "").splitlines()
        matches: List[str] = []

        for line in lines:
            text = line.strip()
            if not text:
                continue
            if apk_name and apk_name in text:
                match = re.search(r"=([A-Za-z0-9_.$]+)$", text)
                if match:
                    matches.append(match.group(1).strip())
            elif file_name and file_name in text:
                match = re.search(r"=([A-Za-z0-9_.$]+)$", text)
                if match:
                    matches.append(match.group(1).strip())

        if matches:
            return matches[0]

        dump = self._run_adb(["-s", device_id, "shell", "dumpsys", "package"], check=False)
        dump_text = dump.stdout or dump.stderr or ""
        # 兜底：部分机型在 dumpsys package 中会暴露 codePath/baseCodePath，结合已安装的 base.apk 名称做模糊匹配
        package_name = ""
        current_package = ""
        for line in dump_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Package ["):
                current_package = stripped[9:]
                current_package = current_package.split("]", 1)[0].strip()
            if apk_name and apk_name in stripped and current_package:
                package_name = current_package
                break
        return package_name

    def _write_dynamic_artifacts(
        self,
        static_report: DetectionReport,
        device_id: str,
        package_name: str,
        package_info: Dict[str, Any],
        granted_permissions: List[str],
        dropped_files: List[str],
        persistent_services: Dict[str, List[str]],
        events: List[Dict[str, Any]],
        logcat_output: str,
    ) -> Dict[str, Any]:
        project_root = Path(__file__).resolve().parents[2]
        output_root = project_root / "information" / "apk_dynamic"
        output_root.mkdir(parents=True, exist_ok=True)

        safe_package_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", package_name or "unknown.package").strip("._-") or "unknown.package"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        run_dir = output_root / f"{timestamp}_{safe_package_name}"
        run_dir.mkdir(parents=True, exist_ok=True)

        json_path = run_dir / "dynamic_artifacts.json"
        summary_path = run_dir / "dynamic_summary.json"
        logcat_path = run_dir / "logcat_excerpt.txt"
        ui_trace_dir = run_dir / "ui_trace"
        ui_trace_paths: List[str] = []
        for label in ("launch", "evidence"):
            screenshot_path = self._capture_ui_screenshot(device_id, ui_trace_dir, package_name, label)
            if screenshot_path:
                ui_trace_paths.append(screenshot_path)
            time.sleep(0.4)
        payload = {
            "target": static_report.target_ir.to_dict(),
            "device_id": device_id,
            "package_name": package_name,
            "runtime_window_seconds": self.runtime_window_seconds,
            "package_info": package_info,
            "granted_dangerous_permissions": granted_permissions,
            "post_install_files": dropped_files,
            "persistent_services": persistent_services,
            "events": events,
            "network_hits": self._extract_network_hits(logcat_output),
            "logcat_excerpt": logcat_output[:20000],
            "ui_trace_paths": ui_trace_paths,
        }
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        summary_path.write_text(json.dumps({
            "device_id": device_id,
            "package_name": package_name,
            "runtime_window_seconds": self.runtime_window_seconds,
            "event_count": len(events),
            "network_hit_count": len(self._extract_network_hits(logcat_output)),
            "target_file": static_report.target_ir.apk.file_name if static_report.target_ir.apk else "",
            "generated_at": timestamp,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        logcat_path.write_text(logcat_output[:20000], encoding="utf-8")
        return {
            "dynamic_json_path": str(json_path.as_posix()),
            "dynamic_json_name": json_path.name,
            "dynamic_summary_path": str(summary_path.as_posix()),
            "dynamic_logcat_path": str(logcat_path.as_posix()),
            "dynamic_output_dir": str(run_dir.as_posix()),
            "ui_trace_dir": str(ui_trace_dir.as_posix()),
            "ui_trace_paths": ui_trace_paths,
        }

    def _build_findings(
        self,
        package_name: str,
        events: List[Dict[str, Any]],
        logcat_output: str,
        granted_permissions: List[str],
        dropped_files: List[str],
        persistent_services: Dict[str, List[str]],
    ) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        lower_logcat = logcat_output.lower()
        if any(event.get("kind") == "crash" for event in events) or "fatal exception" in lower_logcat:
            findings.append(self._finding(
                "APK_DYNAMIC_CRASH", "运行时出现崩溃或致命异常", "high",
                "应用在模拟器中运行时出现崩溃或致命异常，说明样本可能依赖未满足环境、存在异常代码路径或触发了防护逻辑。",
                self._join_event_evidence(events, "crash") or "FATAL EXCEPTION",
                "结合日志与反编译结果确认崩溃点是否与敏感行为相关。",
            ))

        if "anr" in lower_logcat or "application not responding" in lower_logcat:
            findings.append(self._finding(
                "APK_DYNAMIC_ANR", "运行时出现 ANR 线索", "medium",
                "应用在沙箱运行期间出现无响应或阻塞迹象，可能存在阻塞式网络、重计算或异常控制流。",
                "ANR / Application Not Responding", "检查主线程任务、初始化逻辑与后台阻塞调用。",
            ))

        suspicious_network_hits = self._extract_network_hits(logcat_output)
        if suspicious_network_hits:
            findings.append(self._finding(
                "APK_DYNAMIC_NETWORK", "运行时暴露可疑网络线索", "medium",
                "logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。",
                "; ".join(suspicious_network_hits[:5]), "后续可结合抓包或代理进行复核。",
            ))

        suspicious_permissions = [perm for perm in granted_permissions if any(token in perm for token in self.SUSPICIOUS_PERMISSION_KEYWORDS)]
        if suspicious_permissions:
            findings.append(self._finding(
                "APK_DYNAMIC_GRANTED_PERMISSION", "动态运行时暴露高危权限", "high",
                "应用在运行窗口内出现了高危或敏感权限相关线索，需结合业务功能判断是否合理。",
                "; ".join(suspicious_permissions[:10]), "建议确认这些权限是否在动态行为中被真正使用，并继续结合外联/文件落地复核。",
            ))

        if dropped_files:
            findings.append(self._finding(
                "APK_DYNAMIC_PAYLOAD_DROP", "疑似动态载荷释放", "high",
                "运行后在应用目录或临时目录中发现 dex、jar、apk、so、zip 等可疑落地文件。",
                "; ".join(dropped_files[:10]), "建议结合文件哈希、反编译和后续加载日志确认是否存在动态加载或脱壳行为。",
            ))

        persistent_hits = [item for values in persistent_services.values() for item in values]
        if persistent_hits:
            findings.append(self._finding(
                "APK_DYNAMIC_PERSISTENT_SERVICE", "发现持久化或高危服务注册线索", "high",
                "运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。",
                "; ".join(persistent_hits[:10]), "建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。",
            ))

        if not findings:
            findings.append(self._finding(
                "APK_DYNAMIC_BASELINE", "未发现明显运行时异常", "low",
                "模拟器沙箱窗口内未观察到明显崩溃、ANR、可疑联网、文件落地或持久化服务线索。",
                package_name, "建议结合更长窗口或加入抓包/权限交互复测。",
            ))
        return findings

    def _build_summary(
        self,
        static_report: DetectionReport,
        device_id: str,
        package_name: str,
        package_info: Dict[str, Any],
        granted_permissions: List[str],
        dropped_files: List[str],
        persistent_services: Dict[str, List[str]],
        events: List[Dict[str, Any]],
        logcat_output: str,
        install_result: subprocess.CompletedProcess[str],
        launch_result: subprocess.CompletedProcess[str],
    ) -> Dict[str, Any]:
        return {
            "device_id": device_id,
            "package_name": package_name,
            "static_file_name": static_report.target_ir.apk.file_name if static_report.target_ir.apk else "",
            "resolve_activity": package_info.get("resolve_activity", ""),
            "pidof": package_info.get("pidof", ""),
            "granted_dangerous_permissions": granted_permissions,
            "post_install_files": dropped_files,
            "persistent_services": persistent_services,
            "install_success": install_result.returncode == 0,
            "launch_success": launch_result.returncode == 0,
            "event_count": len(events),
            "logcat_excerpt_count": len(logcat_output.splitlines()),
            "network_hit_count": len(self._extract_network_hits(logcat_output)),
            "runtime_window_seconds": self.runtime_window_seconds,
        }

    def _build_dynamic_context(self, static_report: DetectionReport, summary: Dict[str, Any], artifacts: Dict[str, Any], events: List[Dict[str, Any]], logcat_output: str) -> Dict[str, Any]:
        lightweight_target = self._build_lightweight_target_context(static_report.target_ir)
        lightweight_artifacts = self._summarize_dynamic_artifacts(artifacts)
        lightweight_events = self._summarize_dynamic_events(events)
        return {
            "dynamic_summary": self._summarize_dynamic_summary(summary),
            "dynamic_artifacts": lightweight_artifacts,
            "runtime_events": lightweight_events,
            "network_hits": self._extract_network_hits(logcat_output),
            "logcat_excerpt": logcat_output[:6000],
            "static_report": {
                "risk_level": static_report.risk_level,
                "score": static_report.score,
                "findings": [finding.to_dict() for finding in static_report.findings],
                "apk_summary": static_report.apk_summary,
            },
            "target": lightweight_target,
        }

    def _summarize_dynamic_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(summary, dict):
            return {}

        return {
            "device_id": summary.get("device_id", ""),
            "package_name": summary.get("package_name", ""),
            "static_file_name": summary.get("static_file_name", ""),
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

    def _summarize_dynamic_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not isinstance(events, list):
            return []

        compact_events: List[Dict[str, Any]] = []
        for event in events[:20]:
            if not isinstance(event, dict):
                compact_events.append({"text": str(event)[:200]})
                continue
            compact_events.append({
                "kind": event.get("kind", ""),
                "source": event.get("source", ""),
                "returncode": event.get("returncode", 0),
                "stdout": str(event.get("stdout", ""))[:240],
                "stderr": str(event.get("stderr", ""))[:240],
            })
        return compact_events

    def _compact_persistent_services(self, persistent_services: Any) -> Dict[str, List[str]]:
        if not isinstance(persistent_services, dict):
            return {}

        return {
            key: self._limit_list([str(item) for item in value or [] if str(item).strip()], 5)
            for key, value in persistent_services.items()
            if self._limit_list([str(item) for item in value or [] if str(item).strip()], 5)
        }

    def _analyze_dynamic_context(self, static_report: DetectionReport, dynamic_context: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
        analyzer = APKDynamicModelAnalyzer(runtime_config=self.runtime_config, dynamic_context=dynamic_context)
        try:
            return analyzer.analyze(static_report, progress_callback=progress_callback)
        finally:
            if progress_callback:
                progress_callback("dynamic_deep_done", "APK 动态深度研判已完成", 96)

    def _build_lightweight_target_context(self, target_ir) -> Dict[str, Any]:
        target = {
            "target_type": getattr(target_ir, "target_type", ""),
            "original_input": getattr(target_ir, "original_input", ""),
            "status": getattr(target_ir, "status", ""),
            "message": getattr(target_ir, "message", ""),
        }
        apk = getattr(target_ir, "apk", None)
        if apk is not None:
            target["apk"] = self._build_lightweight_apk_context(apk)
        else:
            target["apk"] = None
        url = getattr(target_ir, "url", None)
        if url is not None:
            target["url"] = url.to_dict() if hasattr(url, "to_dict") else url
        else:
            target["url"] = None
        return target

    def _build_lightweight_apk_context(self, apk_ir) -> Dict[str, Any]:
        if not apk_ir:
            return {}

        apk = apk_ir.to_dict() if hasattr(apk_ir, "to_dict") else dict(apk_ir)
        extracted_strings = self._summarize_extracted_strings(apk.get("extracted_strings", []))
        key_files = self._summarize_key_files(apk.get("key_files", []))

        return {
            "normalized_path": apk.get("normalized_path", ""),
            "file_name": apk.get("file_name", ""),
            "package_name": apk.get("package_name", ""),
            "version_name": apk.get("version_name", ""),
            "version_code": apk.get("version_code", ""),
            "sha256": apk.get("sha256", ""),
            "size_bytes": apk.get("size_bytes", 0),
            "permissions": self._limit_list(apk.get("permissions", []), 8),
            "activities": self._limit_list(apk.get("activities", []), 6),
            "services": self._limit_list(apk.get("services", []), 6),
            "receivers": self._limit_list(apk.get("receivers", []), 6),
            "providers": self._limit_list(apk.get("providers", []), 6),
            "certificate_subject": apk.get("certificate_subject", ""),
            "certificate_issuer": apk.get("certificate_issuer", ""),
            "certificate_sha256": apk.get("certificate_sha256", ""),
            "extracted_strings": extracted_strings,
            "extracted_strings_count": len(apk.get("extracted_strings", []) or []),
            "key_files": key_files,
            "key_files_count": len(apk.get("key_files", []) or []),
            "evidence_summary": self._summarize_evidence_summary(apk.get("evidence_summary")),
            "graph_data": self._summarize_graph_data(apk.get("graph_data")),
        }

    @staticmethod
    def _limit_list(values: Any, limit: int) -> List[Any]:
        if not isinstance(values, list):
            return []
        if limit <= 0:
            return []
        return values[:limit]

    def _summarize_extracted_strings(self, strings: Any) -> List[str]:
        if not isinstance(strings, list):
            return []

        suspicious_keywords = (
            "http",
            "https",
            "api",
            "token",
            "password",
            "passwd",
            "secret",
            "cmd",
            "shell",
            "su",
            "root",
            "dex",
            "so",
        )
        suspicious: List[str] = []
        for item in strings:
            text = str(item).strip()
            if not text:
                continue
            if any(keyword in text.lower() for keyword in suspicious_keywords):
                suspicious.append(text)
            if len(suspicious) >= 20:
                break

        if suspicious:
            return suspicious[:8]

        return [str(item).strip() for item in strings[:5] if str(item).strip()]

    def _summarize_key_files(self, key_files: Any) -> List[str]:
        if not isinstance(key_files, list):
            return []

        preview: List[str] = []
        priority_keywords = (
            ".so",
            ".dex",
            "manifest",
            "smali",
            "classes",
            "config",
            "assets",
            "res/",
        )
        for item in key_files:
            text = str(item).strip()
            if not text:
                continue
            preview.append(text)
            if len(preview) >= 12:
                break

        if len(preview) < 12:
            for item in key_files:
                text = str(item).strip()
                if not text or text in preview:
                    continue
                if any(keyword in text.lower() for keyword in priority_keywords):
                    preview.append(text)
                if len(preview) >= 12:
                    break

        return preview[:12]

    def _summarize_evidence_summary(self, evidence_summary: Any) -> Dict[str, Any]:
        if not isinstance(evidence_summary, dict):
            return {}

        summary: Dict[str, Any] = {
            "file_count": evidence_summary.get("file_count") or len(evidence_summary.get("files", []) or []),
            "warnings": self._limit_list([str(item) for item in evidence_summary.get("warnings", []) or [] if str(item).strip()], 5),
            "files_preview": self._limit_list([str(item) for item in evidence_summary.get("files", []) or [] if str(item).strip()], 12),
        }

        for key in ("manifest", "summary", "categories", "signature", "counts"):
            value = evidence_summary.get(key)
            if value:
                summary[key] = value

        return summary

    def _summarize_graph_data(self, graph_data: Any) -> Dict[str, Any]:
        if not graph_data:
            return {}
        if isinstance(graph_data, dict):
            return self._compact_graph_dict(graph_data)

        to_dict = getattr(graph_data, "to_dict", None)
        if callable(to_dict):
            return self._compact_graph_dict(to_dict())

        return {}

    def _compact_graph_dict(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        stats = graph_data.get("stats", {}) if isinstance(graph_data.get("stats", {}), dict) else {}
        compact: Dict[str, Any] = {
            "stats": stats,
            "fallback": bool(graph_data.get("fallback")),
            "fallback_reason": graph_data.get("fallback_reason", ""),
            "warnings": self._limit_list([str(item) for item in graph_data.get("warnings", []) or [] if str(item).strip()], 5),
        }

        for subgraph_name, subgraph in graph_data.items():
            if subgraph_name in {"stats", "fallback", "fallback_reason", "warnings"}:
                continue
            if not isinstance(subgraph, dict):
                compact[subgraph_name] = subgraph
                continue

            compact[subgraph_name] = {
                "node_count": subgraph.get("node_count") or len(subgraph.get("nodes", []) or []),
                "edge_count": subgraph.get("edge_count") or len(subgraph.get("edges", []) or []),
                "nodes_preview": self._limit_list(subgraph.get("nodes", []), 12),
                "edges_preview": self._limit_list(subgraph.get("edges", []), 12),
            }

            if subgraph_name == "api_graph":
                api_counts = subgraph.get("api_call_counts", {}) if isinstance(subgraph.get("api_call_counts", {}), dict) else {}
                compact[subgraph_name]["api_call_counts_top"] = self._limit_dict(api_counts, 12)

        return compact

    @staticmethod
    def _limit_dict(data: Dict[str, Any], limit: int) -> Dict[str, Any]:
        if not isinstance(data, dict) or limit <= 0:
            return {}
        limited: Dict[str, Any] = {}
        for index, (key, value) in enumerate(data.items()):
            if index >= limit:
                break
            limited[key] = value
        return limited

    def _extract_events_from_logcat(self, logcat_output: str, package_name: str) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for line in logcat_output.splitlines():
            lowered = line.lower()
            if package_name.lower() in lowered:
                events.append(self._event("logcat", "logcat", 0, line, ""))
            if "fatal exception" in lowered:
                events.append(self._event("crash", "logcat", 2, line, "fatal exception"))
            if "anr" in lowered or "application not responding" in lowered:
                events.append(self._event("anr", "logcat", 1, line, "anr"))
        return events[:80]

    def _extract_network_hits(self, logcat_output: str) -> List[str]:
        hits: List[str] = []
        patterns = [
            r"https?://[^\s\"'<>]{6,}",
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, logcat_output):
                value = match.strip().rstrip('.,;)]"')
                if value not in hits:
                    hits.append(value)
                if len(hits) >= 12:
                    return hits
        return hits

    def _extract_granted_permissions(self, dumpsys_excerpt: str) -> List[str]:
        granted: List[str] = []
        for line in dumpsys_excerpt.splitlines():
            if "granted=true" not in line and "runtime=true" not in line and "dangerous" not in line.lower():
                continue
            match = re.search(r"android\.permission\.[A-Z0-9_\.]+", line, re.I)
            if match:
                permission = match.group(0).upper()
                if permission not in granted:
                    granted.append(permission)
        return granted

    def _collect_suspicious_files(self, device_id: str, package_name: str) -> List[str]:
        roots = [f"/data/data/{package_name}/", f"/sdcard/Android/data/{package_name}/", "/data/local/tmp/"]
        hits: List[str] = []
        for root in roots:
            result = self._run_adb([
                "-s", device_id, "shell", "sh", "-c",
                f"find '{root}' -type f 2>/dev/null | grep -E '\\.(dex|jar|apk|so|zip)$'"
            ], check=False)
            if result.stdout:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and line not in hits:
                        hits.append(line[:500])
                        if len(hits) >= 20:
                            return hits
        return hits

    def _collect_persistent_services(self, device_id: str, package_name: str) -> Dict[str, List[str]]:
        checks = {
            "accessibility": ["shell", "dumpsys", "accessibility"],
            "device_policy": ["shell", "dumpsys", "device_policy"],
            "notification": ["shell", "dumpsys", "notification"],
        }
        results: Dict[str, List[str]] = {}
        for key, args in checks.items():
            output = self._run_adb(["-s", device_id, *args], check=False)
            matches = [line.strip() for line in (output.stdout or output.stderr or "").splitlines() if package_name in line]
            if matches:
                results[key] = matches[:20]
        return results

    def _join_event_evidence(self, events: List[Dict[str, Any]], kind: str) -> str:
        matches = [event.get("evidence", "") for event in events if event.get("kind") == kind and event.get("evidence")]
        return matches[0] if matches else ""

    def _run_adb(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [self.adb_path, *args]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
        if check and result.returncode != 0:
            raise ApkDynamicAnalyzerError((result.stderr or result.stdout or "adb 命令执行失败").strip())
        return result

    def _event(self, kind: str, source: str, severity: int, stdout: str, stderr: str) -> Dict[str, Any]:
        evidence = (stderr or stdout or "").strip()
        return {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "source": source,
            "severity": severity,
            "evidence": evidence[:1000],
        }

    def _collect_package_info(self, device_id: str, package_name: str) -> Dict[str, Any]:
        dumpsys = self._run_adb(["-s", device_id, "shell", "dumpsys", "package", package_name], check=False)
        resolve = self._run_adb(["-s", device_id, "shell", "cmd", "package", "resolve-activity", "--brief", package_name], check=False)
        pidof = self._run_adb(["-s", device_id, "shell", "pidof", package_name], check=False)
        appops = self._run_adb(["-s", device_id, "shell", "appops", "get", package_name], check=False)
        return {
            "dumpsys_excerpt": (dumpsys.stdout or dumpsys.stderr or "")[:8000],
            "resolve_activity": (resolve.stdout or resolve.stderr or "").strip(),
            "pidof": (pidof.stdout or pidof.stderr or "").strip(),
            "appops_excerpt": (appops.stdout or appops.stderr or "")[:4000],
        }

    def _finding(self, rule_id: str, title: str, severity: str, description: str, evidence: str, recommendation: str) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
        )

    @staticmethod
    def _score_from_findings(findings: List[DetectionFinding]) -> int:
        return score_from_findings(findings)

    @staticmethod
    def _risk_level_from_findings(findings: List[DetectionFinding], fallback: str) -> str:
        score = APKDynamicAnalyzer._score_from_findings(findings)
        return risk_level_from_score(score) if findings else (fallback if fallback in {"low", "medium", "high", "critical"} else "low")


def dynamic_analyze_apk(static_report: DetectionReport, runtime_config: AnalysisRuntimeConfig | None = None, runtime_window_seconds: int = 20, progress_callback=None) -> Dict[str, Any]:
    analyzer = APKDynamicAnalyzer(runtime_window_seconds=runtime_window_seconds, runtime_config=runtime_config)
    return analyzer.analyze(static_report, progress_callback=progress_callback)
