from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config import settings
from SentinelGuard.analyzers.apk_deep_analyzer import APKDeepAnalyzer
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

    def _build_host_payload(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        payload = super()._build_host_payload(static_report, role_outputs)
        payload["dynamic_sandbox"] = self.dynamic_context
        payload["analysis_instruction"] = "主持人必须综合动态沙盒线索与四位专家意见输出最终 risk_level、score、summary、expert_opinions、additional_findings。"
        return payload


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

        package_name = apk_ir.package_name.strip()
        if not package_name:
            raise ApkDynamicAnalyzerError("APK 未解析到包名，无法执行动态安装和启动。")

        if progress_callback:
            progress_callback("dynamic_prepare", "正在准备 APK 动态沙箱", 70)

        self._ensure_adb_available()
        device_id = self._pick_device()

        if progress_callback:
            progress_callback("dynamic_prepare", "正在收集设备与包信息", 72)
        package_info = self._collect_package_info(device_id, package_name)

        if progress_callback:
            progress_callback("dynamic_install", "正在安装 APK 到模拟器", 76)
        self._run_adb(["-s", device_id, "logcat", "-c"], check=False)
        self._run_adb(["-s", device_id, "shell", "logcat", "-c"], check=False)
        install_result = self._run_adb(["-s", device_id, "install", "-r", apk_ir.normalized_path], check=False)

        events: List[Dict[str, Any]] = []
        events.append(self._event("install", "adb", install_result.returncode, install_result.stdout, install_result.stderr))
        if install_result.returncode != 0 and "Success" not in (install_result.stdout or ""):
            raise ApkDynamicAnalyzerError(f"APK 安装失败：{(install_result.stderr or install_result.stdout or '').strip()}")

        if progress_callback:
            progress_callback("dynamic_launch", "正在启动应用并采集运行时日志", 82)
        launch_result = self._launch_package(device_id, package_name)
        events.append(self._event("launch", "adb", launch_result.returncode, launch_result.stdout, launch_result.stderr))

        if progress_callback:
            progress_callback("deep_intel", "正在采集 logcat、权限、文件与持久化线索", 87)
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

        if progress_callback:
            progress_callback("deep_done", "APK 动态沙箱分析已完成", 96)

        return {
            "findings": model_result.get("additional_findings", []),
            "apk_dynamic_summary": summary,
            "apk_dynamic_artifacts": artifacts,
            "expert_opinions": model_result.get("expert_opinions", {}),
            "expert_models": model_result.get("expert_models", {}),
            "deep_summary": model_result.get("deep_summary", ""),
            "risk_level": model_result.get("risk_level", static_report.risk_level),
            "score": model_result.get("score", static_report.score),
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
        return {
            "dynamic_summary": summary,
            "dynamic_artifacts": artifacts,
            "runtime_events": events,
            "network_hits": self._extract_network_hits(logcat_output),
            "logcat_excerpt": logcat_output[:6000],
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


def dynamic_analyze_apk(static_report: DetectionReport, runtime_config: AnalysisRuntimeConfig | None = None, runtime_window_seconds: int = 12, progress_callback=None) -> Dict[str, Any]:
    analyzer = APKDynamicAnalyzer(runtime_window_seconds=runtime_window_seconds, runtime_config=runtime_config)
    return analyzer.analyze(static_report, progress_callback=progress_callback)
