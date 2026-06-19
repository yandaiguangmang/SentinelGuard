from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
import xml.etree.ElementTree as ET

from openai import OpenAI

from config import settings
from SentinelGuard.analyzers.apk_dynamic_explorer import APKDynamicExplorer
from SentinelGuard.analyzers.apk_deep_analyzer import APKDeepAnalyzer, _build_httpx_client, _build_proxy_map, _first_non_empty
from SentinelGuard.scoring import combine_scores, risk_level_from_score, score_from_findings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport


@dataclass
class ApkDynamicRuntimeResult:
    findings: List[DetectionFinding]
    apk_dynamic_summary: Dict[str, Any]
    apk_dynamic_artifacts: Dict[str, Any]
    apk_dynamic_exploration: Dict[str, Any]
    expert_opinions: Dict[str, str]
    expert_models: Dict[str, str]
    deep_summary: str


class ApkDynamicAnalyzerError(RuntimeError):
    pass


class APKDynamicModelAnalyzer(APKDeepAnalyzer):
    EXPLORER_MODEL = "gemini-3.5-flash"

    def __init__(self, runtime_config: AnalysisRuntimeConfig | None, dynamic_context: Dict[str, Any]) -> None:
        self.dynamic_context = dynamic_context
        super().__init__(runtime_config=runtime_config)

    def _build_payload(self, static_report: DetectionReport) -> Dict[str, Any]:
        payload = super()._build_payload(static_report)
        payload["dynamic_sandbox"] = self.dynamic_context
        payload["analysis_instruction"] = "请以 dynamic_sandbox 中整理后的沙盒线索为主要依据进行五角色协同研判，additional_findings 必须来自这些动态线索，不要仅复述静态规则。"
        return payload

    def _build_host_payload(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        payload = super()._build_host_payload(static_report, role_outputs)
        payload["dynamic_sandbox"] = self.dynamic_context
        payload["analysis_instruction"] = "主持人必须综合动态沙盒线索与四位专家意见输出最终 risk_level、score、summary、expert_opinions、additional_findings。"
        return payload

    def _build_explorer_client(self) -> OpenAI | None:
        explorer = APKDynamicExplorer(runtime_config=self.runtime_config, dynamic_context=self.dynamic_context)
        return explorer._build_explorer_client()

    def _build_explorer_payload(self, static_report: DetectionReport, ui_snapshot: Dict[str, Any], exploration_state: Dict[str, Any]) -> Dict[str, Any]:
        explorer = APKDynamicExplorer(runtime_config=self.runtime_config, dynamic_context=self.dynamic_context)
        return explorer._build_explorer_payload(static_report, ui_snapshot, exploration_state)

    def _call_explorer_model(self, static_report: DetectionReport, ui_snapshot: Dict[str, Any], exploration_state: Dict[str, Any]) -> Dict[str, Any]:
        explorer = APKDynamicExplorer(runtime_config=self.runtime_config, dynamic_context=self.dynamic_context)
        return explorer._call_explorer_model(static_report, ui_snapshot, exploration_state)


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
            progress_callback("dynamic_explore_prepare", "正在准备 APK 探索引导员", 84)
        exploration_result = self._run_exploration_loop(static_report, device_id, package_name, progress_callback=progress_callback)

        # 动态探索结束后必须关闭应用，避免后续深度研判阶段继续对目标 App 进行交互。
        try:
            package_info = self._collect_package_info(device_id, package_name)
            logcat_output = self._compose_logcat_output(exploration_result, package_info)
            granted_permissions = self._extract_granted_permissions(package_info.get("dumpsys_excerpt", ""))
            dropped_files = list(exploration_result.get("dropped_files", []))
            persistent_services = dict(exploration_result.get("persistent_services", {}))
            network_hits = list(exploration_result.get("network_hits", []))
            crypto_hits = list(exploration_result.get("crypto_hits", []))

            if progress_callback:
                progress_callback("deep_intel", "正在基于已采集证据进行深度研判", 87)

            events.extend(self._build_runtime_events(exploration_result, package_info, package_name, logcat_output))

            if progress_callback:
                progress_callback("deep_advice", "正在整理动态证据", 92)
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
                exploration_result,
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
                exploration_result,
            )
            dynamic_context = self._build_dynamic_context(static_report, summary, artifacts, events, logcat_output, exploration_result)
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
            merged_findings: List[DetectionFinding] = []
            seen = set()
            for finding in [*sandbox_findings, *model_findings]:
                key = (getattr(finding, "rule_id", ""), getattr(finding, "evidence", ""))
                if key in seen:
                    continue
                seen.add(key)
                merged_findings.append(finding)

            if progress_callback:
                progress_callback("deep_done", "APK 动态沙箱分析已完成", 96)

            return {
                "findings": merged_findings,
                "apk_dynamic_summary": summary,
                "apk_dynamic_artifacts": artifacts,
                "apk_dynamic_exploration": exploration_result,
                "expert_opinions": model_result.get("expert_opinions", {}),
                "expert_models": model_result.get("expert_models", {}),
                "deep_summary": model_result.get("deep_summary", ""),
                "risk_level": model_result.get("risk_level", risk_level_from_score(combine_scores(score_from_findings(merged_findings), model_result.get("deep_score")))),
                "score": combine_scores(score_from_findings(merged_findings), model_result.get("deep_score")),
                "evidence_score": score_from_findings(merged_findings),
                "deep_score": model_result.get("deep_score"),
            }
        finally:
            self._force_stop_package(device_id, package_name)

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
        exploration_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        output_dir = Path(tempfile.gettempdir()) / "sentinelguard_dynamic"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        json_path = output_dir / f"sentinel_apk_dynamic_{package_name}_{timestamp}.json"
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
            "exploration_result": exploration_result,
        }
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "dynamic_json_path": str(json_path.as_posix()),
            "dynamic_json_name": json_path.name,
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
        exploration_result: Dict[str, Any],
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
            "network_hit_count": len(exploration_result.get("network_hits", [])),
            "crypto_hit_count": len(exploration_result.get("crypto_hits", [])),
            "background_snapshot_count": len(exploration_result.get("background_snapshots", [])),
            "runtime_window_seconds": self.runtime_window_seconds,
            "exploration_overview": {
                "total_steps": exploration_result.get("total_steps", 0),
                "visited_control_count": exploration_result.get("visited_control_count", 0),
                "terminated_reason": exploration_result.get("terminated_reason", ""),
                "home_returned": exploration_result.get("home_returned", False),
            },
        }

    def _build_dynamic_context(self, static_report: DetectionReport, summary: Dict[str, Any], artifacts: Dict[str, Any], events: List[Dict[str, Any]], logcat_output: str, exploration_result: Dict[str, Any]) -> Dict[str, Any]:
        background_snapshots = exploration_result.get("background_snapshots", [])
        compact_snapshots: List[Dict[str, Any]] = []
        for snap in background_snapshots[:12]:
            compact_snapshots.append({
                "round": snap.get("round"),
                "step": snap.get("step"),
                "captured_at": snap.get("captured_at"),
                "network_hits": snap.get("network_hits", [])[:5],
                "crypto_hits": snap.get("crypto_hits", [])[:5],
                "granted_permissions": snap.get("granted_permissions", [])[:8],
                "dropped_files": snap.get("dropped_files", [])[:5],
                "persistent_services": snap.get("persistent_services", {}),
                "package_info": {
                    "resolve_activity": (snap.get("package_info") or {}).get("resolve_activity", ""),
                    "pidof": (snap.get("package_info") or {}).get("pidof", ""),
                },
                "logcat_excerpt": str(snap.get("logcat_excerpt") or "")[:2000],
            })
        return {
            "dynamic_summary": summary,
            "dynamic_artifacts": artifacts,
            "runtime_events": events,
            "network_hits": exploration_result.get("network_hits", self._extract_network_hits(logcat_output)),
            "crypto_hits": exploration_result.get("crypto_hits", []),
            "background_snapshots": compact_snapshots,
            "logcat_excerpt": logcat_output[:6000],
            "exploration_trace": exploration_result.get("trace", []),
            "exploration_round_summaries": exploration_result.get("round_summaries", []),
            "exploration_overview": summary.get("exploration_overview", {}),
            "exploration_result": exploration_result,
            "static_report": {
                "risk_level": static_report.risk_level,
                "score": static_report.score,
                "findings": [finding.to_dict() for finding in static_report.findings],
                "apk_summary": static_report.apk_summary,
            },
            "target": static_report.target_ir.to_dict(),
        }

    def _analyze_dynamic_context(self, static_report: DetectionReport, dynamic_context: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
        analyzer = APKDynamicModelAnalyzer(runtime_config=self.runtime_config, dynamic_context=dynamic_context)
        return analyzer.analyze(static_report, progress_callback=progress_callback)

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

    def _extract_crypto_hits(self, logcat_output: str) -> List[str]:
        hits: List[str] = []
        patterns = [
            r"\b(javax\.crypto\.[A-Za-z0-9_$.]+)\b",
            r"\b(java\.security\.[A-Za-z0-9_$.]+)\b",
            r"\b(?:Cipher|MessageDigest|Mac|SecretKey|KeyStore|SecureRandom|Signature|KeyGenerator)\b",
            r"\b(?:AES|DES|RSA|ECDSA|SHA-1|SHA-256|SHA-512|MD5|HmacSHA\d+)\b",
            r"\b(?:encrypt|decrypt|cipher|keystore|hash|digest)\b",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, logcat_output, flags=re.I):
                value = str(match).strip()
                if value and value not in hits:
                    hits.append(value)
                if len(hits) >= 20:
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
        result = self._run_adb(["-s", device_id, "shell", "sh", "-c", "ls -laR " + " ".join(roots) + " 2>/dev/null"], check=False)
        hits: List[str] = []
        for line in (result.stdout or "").splitlines():
            if re.search(r"\.(dex|jar|apk|so|zip)$", line, re.I):
                if line not in hits:
                    hits.append(line[:500])
                if len(hits) >= 20:
                    break
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

    def _capture_background_snapshot(self, device_id: str, package_name: str, round_index: int, step_index: int) -> Dict[str, Any]:
        logcat_output = self._capture_logcat(device_id)
        package_info = self._collect_package_info(device_id, package_name)
        granted_permissions = self._extract_granted_permissions(package_info.get("dumpsys_excerpt", ""))
        dropped_files = self._collect_suspicious_files(device_id, package_name)
        persistent_services = self._collect_persistent_services(device_id, package_name)
        network_hits = self._extract_network_hits(logcat_output)
        crypto_hits = self._extract_crypto_hits(logcat_output)
        self._write_background_snapshot_artifact(
            package_name=package_name,
            round_index=round_index,
            step_index=step_index,
            logcat_output=logcat_output,
            package_info=package_info,
            granted_permissions=granted_permissions,
            dropped_files=dropped_files,
            persistent_services=persistent_services,
            network_hits=network_hits,
            crypto_hits=crypto_hits,
        )
        return {
            "round": round_index + 1,
            "step": step_index + 1,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "logcat_excerpt": logcat_output[:8000],
            "package_info": package_info,
            "granted_permissions": granted_permissions,
            "dropped_files": dropped_files,
            "persistent_services": persistent_services,
            "network_hits": network_hits,
            "crypto_hits": crypto_hits,
        }

    def _write_background_snapshot_artifact(
        self,
        *,
        package_name: str,
        round_index: int,
        step_index: int,
        logcat_output: str,
        package_info: Dict[str, Any],
        granted_permissions: List[str],
        dropped_files: List[str],
        persistent_services: Dict[str, List[str]],
        network_hits: List[str],
        crypto_hits: List[str],
    ) -> None:
        output_dir = Path.cwd() / "information" / "sentinelguard_dynamic" / "background_trace"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        payload = {
            "package_name": package_name,
            "round": round_index + 1,
            "step": step_index + 1,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "logcat_excerpt": logcat_output[:8000],
            "package_info": package_info,
            "granted_permissions": granted_permissions,
            "dropped_files": dropped_files,
            "persistent_services": persistent_services,
            "network_hits": network_hits,
            "crypto_hits": crypto_hits,
        }
        (output_dir / f"{package_name}_r{round_index + 1}_s{step_index + 1}_{stamp}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

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

    def _compose_logcat_output(self, exploration_result: Dict[str, Any], package_info: Dict[str, Any]) -> str:
        excerpts: List[str] = []
        for snapshot in exploration_result.get("background_snapshots", []) or []:
            excerpt = str(snapshot.get("logcat_excerpt") or "").strip()
            if excerpt:
                excerpts.append(excerpt)
        for key in ("dumpsys_excerpt", "appops_excerpt"):
            excerpt = str(package_info.get(key) or "").strip()
            if excerpt:
                excerpts.append(excerpt)
        return "\n".join(excerpts)[:24000]

    def _build_runtime_events(self, exploration_result: Dict[str, Any], package_info: Dict[str, Any], package_name: str, logcat_output: str) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for record in exploration_result.get("trace", []) or []:
            decision = record.get("decision", {}) if isinstance(record, dict) else {}
            action_result = record.get("action_result", {}) if isinstance(record, dict) else {}
            background_snapshot = record.get("background_snapshot", {}) if isinstance(record, dict) else {}
            summary = {
                "round": record.get("round"),
                "step": record.get("step"),
                "action": decision.get("action"),
                "control_index": decision.get("control_index"),
                "reason": decision.get("reason"),
                "action_status": action_result.get("status"),
                "network_hits": background_snapshot.get("network_hits", [])[:5],
                "crypto_hits": background_snapshot.get("crypto_hits", [])[:5],
            }
            events.append(self._event("explore_step", "uiautomator", 0, json.dumps(summary, ensure_ascii=False), ""))

        for hit in exploration_result.get("network_hits", []) or []:
            events.append(self._event("network_hits", "logcat", 0, hit, ""))
        for hit in exploration_result.get("crypto_hits", []) or []:
            events.append(self._event("crypto_hits", "logcat", 0, hit, ""))
        for perm in exploration_result.get("granted_permissions", []) or []:
            events.append(self._event("granted_permissions", "dumpsys", 0, perm, ""))
        for file_hit in exploration_result.get("dropped_files", []) or []:
            events.append(self._event("post_install_files", "adb", 1, file_hit, ""))
        for key, values in (exploration_result.get("persistent_services") or {}).items():
            if values:
                events.append(self._event("persistent_services", key, 2, json.dumps(values[:10], ensure_ascii=False), ""))

        if package_info.get("resolve_activity"):
            events.append(self._event("resolve_activity", "dumpsys", 0, package_info.get("resolve_activity", ""), ""))
        if package_info.get("pidof"):
            events.append(self._event("pidof", "dumpsys", 0, package_info.get("pidof", ""), ""))
        if logcat_output:
            events.append(self._event("logcat_excerpt", "logcat", 0, logcat_output[:2000], ""))
        events.append(self._event("package", "meta", 0, package_name, ""))
        return events

    def _force_stop_package(self, device_id: str, package_name: str) -> None:
        self._run_adb(["-s", device_id, "shell", "am", "force-stop", package_name], check=False)

    def _call_explorer_model(self, static_report: DetectionReport, ui_snapshot: Dict[str, Any], exploration_state: Dict[str, Any]) -> Dict[str, Any]:
        explorer = APKDynamicExplorer(runtime_config=self.runtime_config)
        return explorer._call_explorer_model(static_report, ui_snapshot, exploration_state)

    def _get_interactable_controls(self, controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            control for control in controls
            if control.get("enabled", True)
            and (control.get("clickable") or control.get("focusable") or control.get("scrollable"))
            and self._has_valid_bounds(control)
        ]

    def _has_valid_bounds(self, control: Dict[str, Any]) -> bool:
        bounds = control.get("bounds") or {}
        left = int(bounds.get("left", 0) or 0)
        top = int(bounds.get("top", 0) or 0)
        right = int(bounds.get("right", 0) or 0)
        bottom = int(bounds.get("bottom", 0) or 0)
        return right > left and bottom > top

    def _control_signature(self, control: Dict[str, Any]) -> str:
        return json.dumps(
            {
                "resource_id": str(control.get("resource_id") or "").strip(),
                "text": str(control.get("text") or "").strip().lower(),
                "content_desc": str(control.get("content_desc") or "").strip().lower(),
                "class": str(control.get("class") or "").strip().lower(),
                "bounds": control.get("bounds") or {},
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    def _is_navigation_only_control(self, control: Dict[str, Any]) -> bool:
        label = " ".join([
            str(control.get("text") or ""),
            str(control.get("content_desc") or ""),
            str(control.get("resource_id") or ""),
        ]).lower()
        return any(token in label for token in ("back", "返回", "home", "主页", "首页", "主界面"))

    def _select_explorer_control(
        self,
        decision: Dict[str, Any],
        interactable_controls: List[Dict[str, Any]],
        available_controls: List[Dict[str, Any]],
    ) -> Dict[str, Any] | None:
        if not available_controls:
            return None

        requested_index = int(decision.get("control_index") or 0)
        if 0 <= requested_index < len(interactable_controls):
            requested_control = interactable_controls[requested_index]
            if self._control_signature(requested_control) in {self._control_signature(control) for control in available_controls}:
                return requested_control

        preferred_keywords = ["登录", "密码", "验证码", "账号", "账户", "安全", "隐私", "权限", "支付", "设备", "网络"]
        for keyword in preferred_keywords:
            for control in available_controls:
                if keyword in self._control_label(control):
                    return control

        return available_controls[0]

    def _control_label(self, control: Dict[str, Any]) -> str:
        return " ".join([
            str(control.get("text") or ""),
            str(control.get("content_desc") or ""),
            str(control.get("resource_id") or ""),
            str(control.get("class") or ""),
        ]).strip()

    def _normalize_explorer_decision(self, model_result: Dict[str, Any], ui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        controls = ui_snapshot.get("controls") or []
        fallback_index = int(controls[0]["index"]) if controls else 0
        if not model_result.get("success"):
            return {
                "action": "click",
                "control_index": fallback_index,
                "text": "",
                "reason": str(model_result.get("error") or "模型不可用，回退到第一个可交互控件"),
                "target_hint": "fallback",
            }

        try:
            data = json.loads(model_result.get("content") or "{}")
        except Exception:
            data = {}

        action = str(data.get("action") or "click").lower()
        if action not in {"click", "long_click", "input", "swipe"}:
            action = "click"

        control_index = int(data.get("control_index") or 0)
        if controls:
            control_index = max(0, min(control_index, len(controls) - 1))
        else:
            control_index = 0

        return {
            "action": action,
            "control_index": control_index,
            "text": str(data.get("text") or "").strip(),
            "reason": str(data.get("reason") or "优先探索安全相关功能").strip(),
            "target_hint": str(data.get("target_hint") or "").strip(),
        }

    def _apply_explorer_decision(self, device_id: str, decision: Dict[str, Any], ui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        controls = ui_snapshot.get("controls") or []
        action = decision.get("action") or "click"
        if action in {"back", "home"}:
            return {"status": "skipped", "reason": "动态探索期间禁止退出应用"}

        if not controls:
            return {"status": "skipped", "reason": "未发现可交互控件"}

        index = max(0, min(int(decision.get("control_index") or 0), len(controls) - 1))
        control = controls[index]
        bounds = control.get("bounds") or {}
        center_x = int((bounds.get("left", 0) + bounds.get("right", 0)) / 2)
        center_y = int((bounds.get("top", 0) + bounds.get("bottom", 0)) / 2)

        if action == "swipe":
            self._run_adb(["-s", device_id, "shell", "input", "swipe", "900", "1400", "200", "1400", "400"], check=False)
            return {"status": "ok", "action": action, "control": control}

        if action == "input":
            text = decision.get("text") or self._default_input_text(control)
            self._run_adb(["-s", device_id, "shell", "input", "tap", str(max(center_x, 1)), str(max(center_y, 1))], check=False)
            time.sleep(0.4)
            self._run_adb(["-s", device_id, "shell", "input", "text", self._escape_adb_text(text)], check=False)
            return {"status": "ok", "action": action, "control": control, "text": text}

        if action == "long_click":
            self._run_adb(["-s", device_id, "shell", "input", "swipe", str(max(center_x, 1)), str(max(center_y, 1)), str(max(center_x, 1)), str(max(center_y, 1)), "800"], check=False)
            return {"status": "ok", "action": action, "control": control}

        self._run_adb(["-s", device_id, "shell", "input", "tap", str(max(center_x, 1)), str(max(center_y, 1))], check=False)
        return {"status": "ok", "action": "click", "control": control}

    def _default_input_text(self, control: Dict[str, Any]) -> str:
        label = (control.get("text") or control.get("content_desc") or control.get("resource_id") or "输入").strip()
        if any(token in label for token in ("验证码", "密码", "pin", "PIN")):
            return "123456"
        if any(token in label for token in ("手机", "phone", "手机号")):
            return "13800138000"
        if any(token in label for token in ("邮箱", "email")):
            return "test@example.com"
        if any(token in label for token in ("用户名", "账号", "账户", "login", "user")):
            return "testuser"
        return "test"

    def _escape_adb_text(self, value: str) -> str:
        return value.replace(" ", "%s")

    def _return_to_main_activity(self, device_id: str, package_name: str) -> None:
        activity = self._resolve_main_activity(device_id, package_name)
        if activity:
            self._run_adb([
                "-s", device_id, "shell", "am", "start",
                "-n", activity,
                "-a", "android.intent.action.MAIN",
                "-c", "android.intent.category.LAUNCHER",
            ], check=False)
        else:
            self._run_adb([
                "-s", device_id, "shell", "monkey", "-p", package_name,
                "-c", "android.intent.category.LAUNCHER", "1",
            ], check=False)
        time.sleep(1.0)

    def _resolve_main_activity(self, device_id: str, package_name: str) -> str:
        result = self._run_adb(["-s", device_id, "shell", "cmd", "package", "resolve-activity", "--brief", package_name], check=False)
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            return ""
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in reversed(lines):
            if "/" in line and not line.lower().startswith("priority"):
                return line
        return ""

    def _run_exploration_loop(self, static_report: DetectionReport, device_id: str, package_name: str, progress_callback=None) -> Dict[str, Any]:
        rounds = max(int(getattr(self.runtime_config, "apk_explore_rounds", 3) or 3), 1)
        steps_per_round = max(int(getattr(self.runtime_config, "apk_explore_steps", 5) or 5), 1)
        total_steps = 0
        trace: List[Dict[str, Any]] = []
        round_summaries: List[Dict[str, Any]] = []
        background_snapshots: List[Dict[str, Any]] = []
        network_hits: List[str] = []
        crypto_hits: List[str] = []
        granted_permissions: List[str] = []
        dropped_files: List[str] = []
        persistent_services: Dict[str, List[str]] = {}
        visited_controls: set[str] = set()
        terminated_reason = "round_limit"

        for round_index in range(rounds):
            round_steps: List[Dict[str, Any]] = []
            force_return_home = False
            round_ended_early = False
            for step_index in range(steps_per_round):
                ui_snapshot = self._capture_ui_snapshot(device_id, package_name, round_index, total_steps)
                controls = ui_snapshot.get("controls") or []
                interactable_controls = self._get_interactable_controls(controls)
                available_controls = [control for control in interactable_controls if self._control_signature(control) not in visited_controls]

                if not interactable_controls:
                    terminated_reason = "no_interactable_controls"
                    round_ended_early = True
                    force_return_home = True
                    if progress_callback:
                        progress_callback("dynamic_navigation_only", "当前界面没有其他控件，已返回应用主界面继续探索", 82)
                    break

                if all(self._is_navigation_only_control(control) for control in interactable_controls):
                    terminated_reason = "navigation_only"
                    round_ended_early = True
                    force_return_home = True
                    if progress_callback:
                        progress_callback("dynamic_navigation_only", "当前界面仅有返回/主页类控件，已返回应用主界面继续探索", 82)
                    break

                if not available_controls:
                    terminated_reason = "no_new_controls"
                    round_ended_early = True
                    if progress_callback:
                        progress_callback("dynamic_exhausted", "当前界面已无新的可探索控件，动态探索结束，进入深度研判", 84)
                    break

                exploration_state = {
                    "explore_round": round_index + 1,
                    "explore_step": step_index + 1,
                    "explore_round_limit": rounds,
                    "explore_step_limit": steps_per_round,
                    "global_step": total_steps + 1,
                }
                model_result = self._call_explorer_model(static_report, ui_snapshot, exploration_state)
                decision = self._normalize_explorer_decision(model_result, ui_snapshot)
                selected_control = self._select_explorer_control(decision, interactable_controls, available_controls)
                if selected_control is None:
                    terminated_reason = "no_new_controls"
                    round_ended_early = True
                    if progress_callback:
                        progress_callback("dynamic_exhausted", "当前界面已无新的可探索控件，动态探索结束，进入深度研判", 84)
                    break

                signature = self._control_signature(selected_control)
                visited_controls.add(signature)
                decision["control_index"] = int(selected_control.get("index", 0))
                decision["target_hint"] = decision.get("target_hint") or self._control_label(selected_control)
                action_result = self._apply_explorer_decision(device_id, decision, ui_snapshot)
                background_snapshot = self._capture_background_snapshot(device_id, package_name, round_index, step_index)
                background_snapshots.append(background_snapshot)
                for hit in background_snapshot.get("network_hits", []):
                    if hit not in network_hits:
                        network_hits.append(hit)
                for hit in background_snapshot.get("crypto_hits", []):
                    if hit not in crypto_hits:
                        crypto_hits.append(hit)
                for perm in background_snapshot.get("granted_permissions", []):
                    if perm not in granted_permissions:
                        granted_permissions.append(perm)
                for file_hit in background_snapshot.get("dropped_files", []):
                    if file_hit not in dropped_files:
                        dropped_files.append(file_hit)
                for key, values in (background_snapshot.get("persistent_services") or {}).items():
                    persistent_services.setdefault(key, [])
                    for value in values:
                        if value not in persistent_services[key]:
                            persistent_services[key].append(value)
                record = {
                    "round": round_index + 1,
                    "step": step_index + 1,
                    "global_step": total_steps + 1,
                    "snapshot": ui_snapshot,
                    "decision": decision,
                    "action_result": action_result,
                    "background_snapshot": background_snapshot,
                    "model_result": model_result,
                }
                round_steps.append(record)
                trace.append(record)
                total_steps += 1

                if progress_callback:
                    progress_callback(
                        "dynamic_exploring",
                        f"探索引导员完成第 {round_index + 1} 轮第 {step_index + 1} 步：{decision.get('reason', '正在执行交互')}；后台证据已同步采集",
                        min(90, 84 + int((total_steps / max(rounds * steps_per_round, 1)) * 8)),
                    )

                if total_steps >= rounds * steps_per_round:
                    terminated_reason = "step_limit"
                    force_return_home = True
                    break

                force_return_home = True

            round_summaries.append({
                "round": round_index + 1,
                "step_count": len(round_steps),
                "steps": round_steps,
            })
            if force_return_home:
                self._return_to_main_activity(device_id, package_name)

            if round_ended_early and terminated_reason == "no_new_controls":
                break

            if total_steps >= rounds * steps_per_round:
                break

        return {
            "explore_rounds": rounds,
            "explore_steps": steps_per_round,
            "total_steps": total_steps,
            "trace": trace,
            "round_summaries": round_summaries,
            "background_snapshots": background_snapshots,
            "network_hits": network_hits,
            "crypto_hits": crypto_hits,
            "granted_permissions": granted_permissions,
            "dropped_files": dropped_files,
            "persistent_services": persistent_services,
            "home_returned": True,
            "terminated_reason": terminated_reason,
        }

    def _capture_ui_snapshot(self, device_id: str, package_name: str, round_index: int, step_index: int) -> Dict[str, Any]:
        output_dir = Path.cwd() / "information" / "sentinelguard_dynamic"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base_name = f"{package_name}_r{round_index + 1}_s{step_index + 1}_{stamp}"
        xml_path = output_dir / f"{base_name}.xml"
        screenshot_path = output_dir / f"{base_name}.png"

        self._run_adb(["-s", device_id, "shell", "uiautomator", "dump", "/sdcard/window_dump.xml"], check=False)
        self._run_adb(["-s", device_id, "pull", "/sdcard/window_dump.xml", str(xml_path)], check=False)
        self._run_adb(["-s", device_id, "shell", "screencap", "-p", "/sdcard/window_dump.png"], check=False)
        self._run_adb(["-s", device_id, "pull", "/sdcard/window_dump.png", str(screenshot_path)], check=False)

        xml_text = xml_path.read_text(encoding="utf-8", errors="ignore") if xml_path.exists() else ""
        nodes = self._parse_ui_nodes(xml_text)
        screenshot_data = base64.b64encode(screenshot_path.read_bytes()).decode("utf-8") if screenshot_path.exists() else ""
        return {
            "snapshot_id": base_name,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "screenshot_path": str(screenshot_path.as_posix()),
            "xml_path": str(xml_path.as_posix()),
            "screenshot_data": screenshot_data,
            "controls": nodes,
        }

    def _parse_ui_nodes(self, xml_text: str) -> List[Dict[str, Any]]:
        if not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return []

        controls: List[Dict[str, Any]] = []
        for node in root.iter("node"):
            text = (node.attrib.get("text") or "").strip()
            desc = (node.attrib.get("content-desc") or "").strip()
            clazz = (node.attrib.get("class") or "").strip()
            clickable = node.attrib.get("clickable", "false") == "true"
            focusable = node.attrib.get("focusable", "false") == "true"
            scrollable = node.attrib.get("scrollable", "false") == "true"
            if not (clickable or focusable or scrollable or text or desc):
                continue
            controls.append({
                "index": len(controls),
                "text": text,
                "content_desc": desc,
                "class": clazz,
                "resource_id": (node.attrib.get("resource-id") or "").strip(),
                "clickable": clickable,
                "focusable": focusable,
                "scrollable": scrollable,
                "enabled": node.attrib.get("enabled", "true") == "true",
                "checked": node.attrib.get("checked", "false") == "true",
                "selected": node.attrib.get("selected", "false") == "true",
                "bounds": self._parse_bounds(node.attrib.get("bounds", "")),
            })
        return controls[:80]

    def _parse_bounds(self, bounds_text: str) -> Dict[str, int]:
        numbers = [int(n) for n in re.findall(r"\d+", bounds_text or "")]
        if len(numbers) != 4:
            return {"left": 0, "top": 0, "right": 0, "bottom": 0}
        left, top, right, bottom = numbers
        return {"left": left, "top": top, "right": right, "bottom": bottom}

    def _normalize_explorer_decision(self, model_result: Dict[str, Any], ui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        controls = ui_snapshot.get("controls") or []
        fallback_index = int(controls[0]["index"]) if controls else 0
        if not model_result.get("success"):
            return {
                "action": "click",
                "control_index": fallback_index,
                "text": "",
                "reason": str(model_result.get("error") or "模型不可用，回退到第一个可交互控件"),
                "target_hint": "fallback",
            }

        try:
            data = json.loads(model_result.get("content") or "{}")
        except Exception:
            data = {}

        action = str(data.get("action") or "click").lower()
        if action not in {"click", "long_click", "input", "swipe"}:
            action = "click"

        control_index = int(data.get("control_index") or 0)
        if controls:
            control_index = max(0, min(control_index, len(controls) - 1))
        else:
            control_index = 0

        return {
            "action": action,
            "control_index": control_index,
            "text": str(data.get("text") or "").strip(),
            "reason": str(data.get("reason") or "优先探索安全相关功能").strip(),
            "target_hint": str(data.get("target_hint") or "").strip(),
        }

    def _apply_explorer_decision(self, device_id: str, decision: Dict[str, Any], ui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        controls = ui_snapshot.get("controls") or []
        action = decision.get("action") or "click"
        if action in {"back", "home"}:
            return {"status": "skipped", "reason": "动态探索期间禁止退出应用"}

        if not controls:
            return {"status": "skipped", "reason": "未发现可交互控件"}

        index = max(0, min(int(decision.get("control_index") or 0), len(controls) - 1))
        control = controls[index]
        bounds = control.get("bounds") or {}
        center_x = int((bounds.get("left", 0) + bounds.get("right", 0)) / 2)
        center_y = int((bounds.get("top", 0) + bounds.get("bottom", 0)) / 2)

        if action == "swipe":
            self._run_adb(["-s", device_id, "shell", "input", "swipe", "900", "1400", "200", "1400", "400"], check=False)
            return {"status": "ok", "action": action, "control": control}

        if action == "input":
            text = decision.get("text") or self._default_input_text(control)
            self._run_adb(["-s", device_id, "shell", "input", "tap", str(max(center_x, 1)), str(max(center_y, 1))], check=False)
            time.sleep(0.4)
            self._run_adb(["-s", device_id, "shell", "input", "text", self._escape_adb_text(text)], check=False)
            return {"status": "ok", "action": action, "control": control, "text": text}

        if action == "long_click":
            self._run_adb(["-s", device_id, "shell", "input", "swipe", str(max(center_x, 1)), str(max(center_y, 1)), str(max(center_x, 1)), str(max(center_y, 1)), "800"], check=False)
            return {"status": "ok", "action": action, "control": control}

        self._run_adb(["-s", device_id, "shell", "input", "tap", str(max(center_x, 1)), str(max(center_y, 1))], check=False)
        return {"status": "ok", "action": "click", "control": control}

    def _default_input_text(self, control: Dict[str, Any]) -> str:
        label = (control.get("text") or control.get("content_desc") or control.get("resource_id") or "输入").strip()
        if any(token in label for token in ("验证码", "密码", "pin", "PIN")):
            return "123456"
        if any(token in label for token in ("手机", "phone", "手机号")):
            return "13800138000"
        if any(token in label for token in ("邮箱", "email")):
            return "test@example.com"
        if any(token in label for token in ("用户名", "账号", "账户", "login", "user")):
            return "testuser"
        return "test"

    def _escape_adb_text(self, value: str) -> str:
        return value.replace(" ", "%s")

    def _return_to_home(self, device_id: str) -> None:
        # 保留兼容接口，但动态探索流程中不再主动发送 HOME 键。
        return

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


def dynamic_analyze_apk(static_report: DetectionReport, runtime_config: AnalysisRuntimeConfig | None = None, runtime_window_seconds: int = 12, progress_callback=None) -> Dict[str, Any]:
    analyzer = APKDynamicAnalyzer(runtime_window_seconds=runtime_window_seconds, runtime_config=runtime_config)
    return analyzer.analyze(static_report, progress_callback=progress_callback)
