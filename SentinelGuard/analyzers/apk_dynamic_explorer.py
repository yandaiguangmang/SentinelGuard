from __future__ import annotations

import base64
import json
import re
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
import xml.etree.ElementTree as ET
import subprocess

from openai import OpenAI

from config import settings
from SentinelGuard.analyzers.apk_deep_analyzer import APKDeepAnalyzer, _build_httpx_client, _build_proxy_map, _first_non_empty
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionReport


class APKDynamicExplorer(APKDeepAnalyzer):
    """APK 动态探索执行器：仅负责界面采集、引导员决策和交互执行。"""

    EXPLORER_MODEL = "gemini-3.5-flash"

    def __init__(self, runtime_config: AnalysisRuntimeConfig | None, dynamic_context: Dict[str, Any] | None = None) -> None:
        self.dynamic_context = dynamic_context or {}
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
        api_key = _first_non_empty(
            self.runtime_config.llm_api_key,
            settings.DETECTION_HOST_API_KEY,
            settings.FORUM_HOST_API_KEY,
        )
        base_url = _first_non_empty(
            self.runtime_config.llm_base_url,
            settings.DETECTION_HOST_BASE_URL,
            settings.FORUM_HOST_BASE_URL,
        )
        if not api_key:
            return None

        client_kwargs: Dict[str, Any] = {"api_key": api_key}
        proxy_map = _build_proxy_map(self.runtime_config)
        if proxy_map:
            client_kwargs["http_client"] = _build_httpx_client(proxy_map)
        if base_url:
            client_kwargs["base_url"] = base_url
        return OpenAI(**client_kwargs)

    def _build_explorer_payload(self, static_report: DetectionReport, ui_snapshot: Dict[str, Any], exploration_state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": static_report.target_ir.to_dict(),
            "static_report": {
                "risk_level": static_report.risk_level,
                "score": static_report.score,
                "findings": [finding.to_dict() for finding in static_report.findings],
                "apk_summary": static_report.apk_summary,
            },
            "ui_snapshot": ui_snapshot,
            "exploration_state": exploration_state,
            "instruction": "请从当前界面的控件中选择一个最值得继续探索的控件，优先选择与登录、权限、账户、安全、隐私、支付、验证码、设备信息、网络配置相关的功能。动态探索期间禁止退出应用，不要选择 back 或 home。输出严格 JSON：{\"action\":\"click|long_click|input|swipe\",\"control_index\":0,\"text\":\"可选输入内容\",\"reason\":\"选择理由\",\"target_hint\":\"控件特征摘要\"}。",
        }

    def _call_explorer_model(self, static_report: DetectionReport, ui_snapshot: Dict[str, Any], exploration_state: Dict[str, Any]) -> Dict[str, Any]:
        client = self._build_explorer_client()
        payload = self._build_explorer_payload(static_report, ui_snapshot, exploration_state)
        if client is None:
            return {"success": False, "error": "未配置探索引导员 API Key"}

        image_data = ui_snapshot.get("screenshot_data") or ""
        user_content: List[Dict[str, Any]] = [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}]
        if image_data:
            user_content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_data}"}})

        try:
            response = client.chat.completions.create(
                model=self.EXPLORER_MODEL,
                messages=[
                    {"role": "system", "content": "你是 APK 动态探索引导员，只负责根据当前界面选择下一步操作，不参与最终论坛式深度研判。"},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.2,
                top_p=0.9,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content if response.choices else ""
            if not content:
                return {"success": False, "error": "探索引导员未返回内容"}
            return {"success": True, "content": content}
        except Exception as exc:
            return {"success": False, "error": f"探索引导员调用异常: {exc}"}

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

    def _get_interactable_controls(self, controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            control for control in controls
            if (
                control.get("enabled", True)
                and (control.get("clickable") or control.get("focusable") or control.get("scrollable"))
                and self._has_valid_bounds(control)
            )
        ]

    def _has_valid_bounds(self, control: Dict[str, Any]) -> bool:
        bounds = control.get("bounds") or {}
        left = int(bounds.get("left", 0) or 0)
        top = int(bounds.get("top", 0) or 0)
        right = int(bounds.get("right", 0) or 0)
        bottom = int(bounds.get("bottom", 0) or 0)
        return right > left and bottom > top

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
        result = self._run_adb([
            "-s", device_id, "shell", "cmd", "package", "resolve-activity", "--brief", package_name,
        ], check=False)
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            return ""
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in reversed(lines):
            if "/" in line and not line.lower().startswith("priority"):
                return line
        return ""

    def run_exploration_loop(self, static_report: DetectionReport, device_id: str, package_name: str, progress_callback=None) -> Dict[str, Any]:
        rounds = max(int(getattr(self.runtime_config, "apk_explore_rounds", 3) or 3), 1)
        steps_per_round = max(int(getattr(self.runtime_config, "apk_explore_steps", 5) or 5), 1)
        total_limit = rounds * steps_per_round
        total_steps = 0
        trace: List[Dict[str, Any]] = []
        round_summaries: List[Dict[str, Any]] = []
        visited_controls: set[str] = set()
        exhausted_due_to_new_controls = False

        for round_index in range(rounds):
            round_steps: List[Dict[str, Any]] = []
            for step_index in range(steps_per_round):
                ui_snapshot = self.capture_ui_snapshot(device_id, package_name, round_index, total_steps)
                controls = ui_snapshot.get("controls") or []
                interactable_controls = self._get_interactable_controls(controls)
                available_controls = [control for control in interactable_controls if self._control_signature(control) not in visited_controls]

                if not interactable_controls or all(self._is_navigation_only_control(control) for control in interactable_controls):
                    if progress_callback:
                        progress_callback(
                            "dynamic_navigation_only",
                            "当前界面仅包含返回或主页类操作，动态探索结束后将返回应用主界面",
                            min(82, 72 + round_index * 2),
                        )
                    exhausted_due_to_new_controls = True
                    break

                if not available_controls:
                    exhausted_due_to_new_controls = True
                    if progress_callback:
                        progress_callback(
                            "dynamic_exhausted",
                            "当前界面已无新的可探索控件，动态探索提前结束，进入深度研判",
                            84,
                        )
                    break

                exploration_state = {
                    "explore_round": round_index + 1,
                    "explore_step": step_index + 1,
                    "explore_round_limit": rounds,
                    "explore_step_limit": steps_per_round,
                    "global_step": total_steps + 1,
                }
                model_result = self._call_explorer_model(static_report, ui_snapshot, exploration_state)
                decision = self.normalize_explorer_decision(model_result, ui_snapshot)
                selected_control = self._select_explorer_control(decision, interactable_controls, available_controls)
                if selected_control is None:
                    exhausted_due_to_new_controls = True
                    if progress_callback:
                        progress_callback(
                            "dynamic_exhausted",
                            "当前界面已无新的可探索控件，动态探索提前结束，进入深度研判",
                            84,
                        )
                    break

                selected_signature = self._control_signature(selected_control)
                visited_controls.add(selected_signature)
                decision["control_index"] = int(selected_control.get("index", 0))
                decision["target_hint"] = decision.get("target_hint") or self._control_label(selected_control)
                action_result = self.apply_explorer_decision(device_id, decision, ui_snapshot)
                record = {
                    "round": round_index + 1,
                    "step": step_index + 1,
                    "global_step": total_steps + 1,
                    "snapshot": ui_snapshot,
                    "decision": decision,
                    "action_result": action_result,
                    "model_result": model_result,
                }
                round_steps.append(record)
                trace.append(record)
                total_steps += 1

                if progress_callback:
                    progress_callback(
                        "dynamic_exploring",
                        f"探索引导员完成第 {round_index + 1} 轮第 {step_index + 1} 步：{decision.get('reason', '正在执行交互')}",
                        min(84, 66 + int((total_steps / max(total_limit, 1)) * 18)),
                    )

                if total_steps >= total_limit:
                    break

            round_summaries.append({
                "round": round_index + 1,
                "step_count": len(round_steps),
                "steps": round_steps,
            })
            if exhausted_due_to_new_controls or total_steps >= total_limit:
                break

            # 每轮探索结束后返回当前应用的主界面，继续后续探索。

        return {
            "explore_rounds": rounds,
            "explore_steps": steps_per_round,
            "total_steps": total_steps,
            "trace": trace,
            "round_summaries": round_summaries,
            "home_returned": True,
            "visited_control_count": len(visited_controls),
            "terminated_reason": "no_new_controls" if exhausted_due_to_new_controls else "round_limit",
        }

    def capture_ui_snapshot(self, device_id: str, package_name: str, round_index: int, step_index: int) -> Dict[str, Any]:
        output_dir = Path.cwd() / "information" / "sentinelguard_dynamic" / "ui_trace"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base_name = f"{package_name}_r{round_index + 1}_s{step_index + 1}_{stamp}"
        xml_path = output_dir / f"{base_name}.xml"
        screenshot_path = output_dir / f"{base_name}.png"
        controls_path = output_dir / f"{base_name}.json"

        dump_result = self._run_adb(["-s", device_id, "shell", "uiautomator", "dump", "/sdcard/window_dump.xml"], check=False)
        if dump_result.returncode == 0:
            pulled = self._run_adb(["-s", device_id, "pull", "/sdcard/window_dump.xml", str(xml_path)], check=False)
            if pulled.returncode != 0 or not xml_path.exists():
                self._save_text_snapshot_fallback(device_id, xml_path)
        else:
            self._save_text_snapshot_fallback(device_id, xml_path)

        screenshot_ok = self._capture_screenshot(device_id, screenshot_path)

        xml_text = xml_path.read_text(encoding="utf-8", errors="ignore") if xml_path.exists() else ""
        nodes = self.parse_ui_nodes(xml_text)
        screenshot_data = base64.b64encode(screenshot_path.read_bytes()).decode("utf-8") if screenshot_path.exists() else ""
        controls_payload = {
            "snapshot_id": base_name,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "package_name": package_name,
            "round_index": round_index + 1,
            "step_index": step_index + 1,
            "xml_path": str(xml_path.as_posix()),
            "screenshot_path": str(screenshot_path.as_posix()),
            "screenshot_saved": screenshot_ok,
            "controls": nodes,
        }
        controls_path.write_text(json.dumps(controls_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "snapshot_id": base_name,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "screenshot_path": str(screenshot_path.as_posix()),
            "xml_path": str(xml_path.as_posix()),
            "controls_path": str(controls_path.as_posix()),
            "screenshot_saved": screenshot_ok,
            "screenshot_data": screenshot_data,
            "controls": nodes,
        }

    def _capture_screenshot(self, device_id: str, screenshot_path: Path) -> bool:
        """优先使用 exec-out 直接导出 PNG，避免某些设备 pull 后文件损坏或丢失。"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "exec-out", "screencap", "-p"],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                screenshot_path.write_bytes(result.stdout)
                if screenshot_path.exists() and screenshot_path.stat().st_size > 0:
                    return True
        except Exception:
            pass

        self._run_adb(["-s", device_id, "shell", "screencap", "-p", "/sdcard/window_dump.png"], check=False)
        pulled = self._run_adb(["-s", device_id, "pull", "/sdcard/window_dump.png", str(screenshot_path)], check=False)
        return pulled.returncode == 0 and screenshot_path.exists() and screenshot_path.stat().st_size > 0

    def _save_text_snapshot_fallback(self, device_id: str, xml_path: Path) -> None:
        """uiautomator dump 失败时，尽量从设备端直接读取 XML 内容。"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "cat", "/sdcard/window_dump.xml"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
            content = (result.stdout or result.stderr or "").strip()
            if content:
                xml_path.write_text(content, encoding="utf-8")
        except Exception:
            return

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
            requested_signature = self._control_signature(requested_control)
            if requested_signature in {self._control_signature(control) for control in available_controls}:
                return requested_control

        preferred_labels = ["登录", "密码", "验证码", "账户", "账号", "安全", "隐私", "权限", "支付", "设备", "网络"]
        for keyword in preferred_labels:
            for control in available_controls:
                label = self._control_label(control)
                if keyword in label:
                    return control

        return available_controls[0]

    def _control_label(self, control: Dict[str, Any]) -> str:
        return " ".join([
            str(control.get("text") or ""),
            str(control.get("content_desc") or ""),
            str(control.get("resource_id") or ""),
            str(control.get("class") or ""),
        ]).strip()

    def parse_ui_nodes(self, xml_text: str) -> List[Dict[str, Any]]:
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
                "bounds": self.parse_bounds(node.attrib.get("bounds", "")),
            })
        return controls[:80]

    def parse_bounds(self, bounds_text: str) -> Dict[str, int]:
        numbers = [int(n) for n in re.findall(r"\d+", bounds_text or "")]
        if len(numbers) != 4:
            return {"left": 0, "top": 0, "right": 0, "bottom": 0}
        left, top, right, bottom = numbers
        return {"left": left, "top": top, "right": right, "bottom": bottom}

    def normalize_explorer_decision(self, model_result: Dict[str, Any], ui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
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

    def apply_explorer_decision(self, device_id: str, decision: Dict[str, Any], ui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
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

        if center_x <= 0 or center_y <= 0:
            return {"status": "skipped", "reason": "控件坐标无效，跳过本次交互"}

        if action == "swipe":
            self._run_adb(["-s", device_id, "shell", "input", "swipe", "900", "1400", "200", "1400", "400"], check=False)
            return {"status": "ok", "action": action, "control": control}

        if action == "input":
            text = decision.get("text") or self.default_input_text(control)
            self._run_adb(["-s", device_id, "shell", "input", "tap", str(max(center_x, 1)), str(max(center_y, 1))], check=False)
            time.sleep(0.4)
            self._run_adb(["-s", device_id, "shell", "input", "text", self.escape_adb_text(text)], check=False)
            return {"status": "ok", "action": action, "control": control, "text": text}

        if action == "long_click":
            self._run_adb(["-s", device_id, "shell", "input", "swipe", str(max(center_x, 1)), str(max(center_y, 1)), str(max(center_x, 1)), str(max(center_y, 1)), "800"], check=False)
            return {"status": "ok", "action": action, "control": control}

        self._run_adb(["-s", device_id, "shell", "input", "tap", str(max(center_x, 1)), str(max(center_y, 1))], check=False)
        return {"status": "ok", "action": "click", "control": control}

    def default_input_text(self, control: Dict[str, Any]) -> str:
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

    def escape_adb_text(self, value: str) -> str:
        return value.replace(" ", "%s")

    def return_to_home(self, device_id: str) -> None:
        # 保留兼容接口，但动态探索流程中不再主动发送 HOME 键。
        return