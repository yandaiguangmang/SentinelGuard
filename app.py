from __future__ import annotations

import copy
import logging
import threading
import tempfile
from pathlib import Path
from typing import Any, Dict

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

from SentinelGuard.judgement import (
    run_apk_deep_detection_from_static,
    run_deep_url_detection_from_static,
    run_detection,
    run_static_detection,
)
from SentinelGuard.analyzers.apk_dynamic_analyzer import dynamic_analyze_apk
from SentinelGuard.report import _deduplicate_semantic_findings, save_detection_report
from SentinelGuard.scoring import combine_apk_scores, risk_level_from_score, score_from_findings
from SentinelGuard.task_manager import task_manager
from SentinelGuard.state import AnalysisRuntimeConfig, ArbitrationResult, RobustnessResult
from config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "SentinelGuard-URL-Security-Web"
app.config["MAX_CONTENT_LENGTH"] = getattr(settings, "MAX_UPLOAD_SIZE", 500 * 1024 * 1024)

logging.getLogger("werkzeug").setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)


@app.get("/")
def index():
    return render_template("index.html", report=None, error=None, defaults={
        "target": "",
        "target_type": "auto",
        "fetch_page": True,
        "enable_screenshot": getattr(settings, "DETECTION_ENABLE_SCREENSHOT", True),
        "deep": False,
        "apk_deep": False,
        "apk_mode": "static",
        "llm_api_key": "",
        "proxy_http": "",
        "proxy_https": "",
        "proxy_all": "",
    })


@app.post("/analyze")
def analyze():
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        task = _start_analysis_task_from_request(request)
        return jsonify({"task_id": task.task_id, "status": task.status, "progress": task.progress})

    target = (request.form.get("target") or "").strip()
    target_type = (request.form.get("target_type") or "auto").strip()
    fetch_page = request.form.get("fetch_page") == "on"
    deep = request.form.get("deep") == "on"
    apk_deep = request.form.get("apk_deep") == "on"
    apk_mode = (request.form.get("apk_mode") or "static").strip()
    enable_screenshot = request.form.get("enable_screenshot") == "on"
    runtime_config = _build_runtime_config(request.form)

    uploaded_apks = request.files.getlist("apk_file") if request.files else []
    apk_files = [item for item in uploaded_apks if item and item.filename]
    if apk_files:
        if any(Path(item.filename).suffix.lower() != ".apk" for item in apk_files):
            return render_template("index.html", report=None, error="请上传 .apk 文件", defaults={
                "target": target,
                "target_type": target_type,
                "fetch_page": fetch_page,
                "deep": deep,
                "apk_deep": apk_deep,
                "apk_mode": apk_mode,
                **runtime_config.to_dict(),
            })
        target = _save_uploaded_apk_bundle(apk_files)
        target_type = "apk"

    if not target:
        return render_template("index.html", report=None, error="请输入待检测的 URL 或上传 APK 文件", defaults={
            "target": target,
            "target_type": target_type,
            "fetch_page": fetch_page,
            "deep": deep,
            "apk_deep": apk_deep,
            "apk_mode": apk_mode,
            **runtime_config.to_dict(),
        })

    report = (
        run_static_detection(target, target_type=target_type, fetch_page=fetch_page, persist_report=False, runtime_config=runtime_config)
        if target_type == "apk"
        else run_detection(target, target_type=target_type, fetch_page=fetch_page, runtime_config=runtime_config)
    )
    try:
        if report.target_ir.target_type == "apk":
            report = _generate_apk_report_bundle(
                static_report=report,
                apk_mode=apk_mode,
                apk_deep=apk_deep,
                runtime_config=runtime_config,
            )
        elif deep:
            report = run_deep_url_detection_from_static(report, persist_report=False, runtime_config=runtime_config)
    except Exception as exc:
        return render_template("index.html", report=report, error=f"深度研判失败，已返回静态结果：{exc}", defaults={
            "target": target,
            "target_type": target_type,
            "fetch_page": fetch_page,
            "deep": deep,
            "apk_deep": apk_deep,
            "apk_mode": apk_mode,
            **runtime_config.to_dict(),
        })

    if report.target_ir.target_type != "apk":
        report = save_detection_report(report, output_dir=Path(settings.DETECTION_REPORT_DIR))
    return render_template("index.html", report=report, error=None, defaults={
        "target": target,
        "target_type": target_type,
        "fetch_page": fetch_page,
            "enable_screenshot": getattr(settings, "DETECTION_ENABLE_SCREENSHOT", True),
        "deep": deep,
        "apk_deep": apk_deep,
        "apk_mode": apk_mode,
        **runtime_config.to_dict(),
    })


@app.post("/tasks/analyze")
def start_analysis_task():
    task = _start_analysis_task_from_request(request)
    return jsonify({"task_id": task.task_id, "status": task.status, "progress": task.progress})


@app.get("/tasks/<task_id>")
def get_task_status(task_id: str):
    task = task_manager.get(task_id)
    if not task:
        abort(404)
    data = task.to_dict()
    if task.result:
        data["result"] = task.result
    return jsonify(data)


def _start_analysis_task_from_request(req):
    payload = req.get_json(silent=True) or req.form.to_dict(flat=True)
    target = (payload.get("target") or "").strip()
    target_type = (payload.get("target_type") or "auto").strip()
    fetch_page = str(payload.get("fetch_page") or "") in {"on", "true", "1", "yes"}
    enable_screenshot = str(payload.get("enable_screenshot") or "") in {"on", "true", "1", "yes"}
    deep = str(payload.get("deep") or "") in {"on", "true", "1", "yes"}
    apk_deep = str(payload.get("apk_deep") or "") in {"on", "true", "1", "yes"}
    apk_mode = str(payload.get("apk_mode") or "static").strip()
    runtime_config = _build_runtime_config(payload)

    uploaded_apks = req.files.getlist("apk_file") if hasattr(req, "files") else []
    apk_files = [item for item in uploaded_apks if item and item.filename]
    if apk_files:
        if any(Path(item.filename).suffix.lower() != ".apk" for item in apk_files):
            raise ValueError("请上传 .apk 文件")
        target = _save_uploaded_apk_bundle(apk_files)
        target_type = "apk"

    uploaded_path = payload.get("uploaded_path") or ""
    if uploaded_path:
        target = str(uploaded_path).strip()
        target_type = "apk"

    task = task_manager.create(target_type=target_type)
    task_manager.update(task.task_id, status="running", progress=5, stage="received", message="任务已接收，准备开始分析")

    thread = threading.Thread(
        target=_run_analysis_pipeline,
        args=(task.task_id, target, target_type, fetch_page, deep, apk_deep, apk_mode, runtime_config),
        daemon=True,
    )
    thread.start()
    return task


def _run_analysis_pipeline(task_id: str, target: str, target_type: str, fetch_page: bool, deep: bool, apk_deep: bool, apk_mode: str, runtime_config: AnalysisRuntimeConfig) -> None:
    try:
        task_manager.update(task_id, status="running", progress=10, stage="static", message="正在进行静态分析")
        report = (
            run_static_detection(target, target_type=target_type, fetch_page=fetch_page, persist_report=False, runtime_config=runtime_config)
            if target_type == "apk"
            else run_detection(target, target_type=target_type, fetch_page=fetch_page, runtime_config=runtime_config)
        )
        task_manager.update(task_id, progress=62, stage="static_done", message="静态分析已完成，正在整理证据")

        progress_callback = lambda stage, message, progress: task_manager.update(  # noqa: E731
            task_id,
            progress=progress,
            stage=stage,
            message=message,
        )

        if report.target_ir.target_type == "apk":
            report = _generate_apk_report_bundle(
                static_report=report,
                apk_mode=apk_mode,
                apk_deep=apk_deep,
                runtime_config=runtime_config,
                progress_callback=progress_callback,
                task_id=task_id,
            )
            if apk_mode == "dynamic" and apk_deep:
                task_manager.update(task_id, progress=94, stage="dynamic_deep_done", message="APK 动态深度研判已完成，正在生成报告")
            elif apk_mode == "dynamic":
                task_manager.update(task_id, progress=94, stage="dynamic_done", message="APK 动态沙箱已完成，正在生成报告")
            elif apk_deep:
                task_manager.update(task_id, progress=94, stage="deep_done", message="深度研判已完成，正在生成报告")
            else:
                task_manager.update(task_id, progress=88, stage="static_only", message="静态分析完成，正在生成报告")
        else:
            if deep:
                report = run_deep_url_detection_from_static(
                    report,
                    persist_report=False,
                    runtime_config=runtime_config,
                    progress_callback=progress_callback,
                )
                task_manager.update(task_id, progress=94, stage="deep_done", message="深度研判已完成，正在生成报告")
            else:
                task_manager.update(task_id, progress=88, stage="static_only", message="静态分析完成，正在生成报告")

        if report.target_ir.target_type != "apk":
            report = save_detection_report(report, output_dir=Path(settings.DETECTION_REPORT_DIR))
        task_manager.finish(task_id, report.to_dict())
    except Exception as exc:
        task_manager.fail(task_id, str(exc))


def _generate_apk_report_bundle(
    static_report,
    apk_mode: str,
    apk_deep: bool,
    runtime_config: AnalysisRuntimeConfig,
    progress_callback=None,
    task_id: str | None = None,
):
    """根据 APK 分析模式生成并保存对应报告。

    约定：
    - 仅保存当前模式对应的最终报告
    - 静态分析结果仅作为后续动态/深度报告的中间输入，不单独落盘
    """

    def _persist(report):
        return save_detection_report(report, output_dir=Path(settings.DETECTION_REPORT_DIR))

    # 静态模式：只保存静态报告
    if apk_mode != "dynamic" and not apk_deep:
        return _persist(static_report)

    # 静态 + 深度：只保存最终深度报告，静态报告仅作为中间输入
    if apk_mode != "dynamic":
        if apk_deep:
            deep_report = run_apk_deep_detection_from_static(static_report, persist_report=False, runtime_config=runtime_config, progress_callback=progress_callback)
            return _persist(deep_report)
        return static_report

    if progress_callback:
        progress_callback("apk_dynamic_prepare", "正在生成仅动态沙箱报告", 84)
    dynamic_result = dynamic_analyze_apk(
        static_report,
        runtime_config=runtime_config,
        progress_callback=progress_callback,
        enable_deep_model=apk_deep,
    )
    dynamic_report = _build_apk_report_from_dynamic_result(
        static_report=static_report,
        dynamic_result=dynamic_result,
        analysis_mode="dynamic",
        include_deep_model=False,
        parent_html_report_path="",
        parent_markdown_report_path="",
    )

    if not apk_deep:
        return _persist(dynamic_report)

    if progress_callback:
        progress_callback("apk_dynamic_deep", "正在生成动态深度研判报告", 92)
    deep_report = _build_apk_report_from_dynamic_result(
        static_report=static_report,
        dynamic_result=dynamic_result,
        analysis_mode="deep",
        include_deep_model=True,
        parent_html_report_path="",
        parent_markdown_report_path="",
    )
    deep_report.placeholders = {
        **(deep_report.placeholders or {}),
    }
    if task_id:
        task_manager.update(task_id, progress=95, stage="apk_bundle_ready", message="APK 深度报告已准备完成，正在收尾")
    return _persist(deep_report)


def _build_apk_report_from_dynamic_result(
    static_report,
    dynamic_result: Dict[str, Any],
    analysis_mode: str,
    include_deep_model: bool,
    parent_html_report_path: str = "",
    parent_markdown_report_path: str = "",
):
    target_ir = copy.deepcopy(static_report.target_ir)
    arbitration_result = None
    robustness_result = None
    if target_ir.apk is not None:
        arbitration_result = _coerce_arbitration_result(dynamic_result.get("arbitration_result"))
        robustness_result = _coerce_robustness_result(dynamic_result.get("robustness_result"))
        target_ir.apk.arbitration_result = arbitration_result
        target_ir.apk.robustness = robustness_result or target_ir.apk.robustness


    if include_deep_model:
        # 开启深度研判时，使用 dynamic_result 中的 findings（已包含静态 + 动态 + 模型证据）
        findings = _deduplicate_semantic_findings(dynamic_result.get("findings", []))
    else:
        # 未开启深度研判时，dynamic_result 中的 findings 已经包含了所有证据
        # 直接使用，避免与 static_report.findings 重复组合导致不一致
        findings = _deduplicate_semantic_findings(dynamic_result.get("findings", []))

    # 如果 dynamic_result 中没有 findings（兜底），才使用静态报告的证据
    if not findings:
        sandbox_findings = dynamic_result.get("sandbox_findings") or []
        findings = _deduplicate_semantic_findings([
            *list(static_report.findings or []),
            *list(sandbox_findings or []),
        ])

    evidence_score = dynamic_result.get("evidence_score")
    if evidence_score is None:
        evidence_score = score_from_findings(findings)

    deep_score = dynamic_result.get("deep_score") if include_deep_model else None

    score = int(dynamic_result.get("score") or combine_apk_scores(
        evidence_score,
        deep_score,
        arbitration_result if include_deep_model else None,
        robustness_result,
    ))
    risk_level = str(risk_level_from_score(score))

    report = static_report.__class__(
        target_ir=target_ir,
        risk_level=risk_level,
        score=score,
        evidence_score=evidence_score,
        deep_score=deep_score,
        findings=findings,
        expert_opinions=dynamic_result.get("expert_opinions", static_report.expert_opinions),
        expert_models=dynamic_result.get("expert_models", {} if not include_deep_model else dynamic_result.get("expert_models", {})),
        deep_summary=dynamic_result.get("deep_summary", "") if include_deep_model else "当前未开启深度研判，仅输出动态沙箱采集证据与静态规则匹配结果。",
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        apk_summary=static_report.apk_summary,
        apk_dynamic_summary=dynamic_result.get("apk_dynamic_summary", {}),
        apk_dynamic_artifacts=dynamic_result.get("apk_dynamic_artifacts", {}),
        placeholders=static_report.placeholders,
        screenshots=static_report.screenshots,
        analysis_mode=analysis_mode,
        deep_analysis_used=include_deep_model,
        parent_html_report_path=parent_html_report_path,
        parent_markdown_report_path=parent_markdown_report_path,
        arbitration_result=arbitration_result if include_deep_model else None,
        stats=dynamic_result.get("stats") if isinstance(dynamic_result.get("stats"), dict) else None,
    )
    return report


def _coerce_arbitration_result(value):
    if value is None or isinstance(value, ArbitrationResult):
        return value
    if isinstance(value, dict):
        return ArbitrationResult(
            consistency_score=float(value.get("consistency_score", 0.0) or 0.0),
            consistency_level=str(value.get("consistency_level", "low") or "low"),
            discrepancies=list(value.get("discrepancies", []) or []),
            suspected_compromised=list(value.get("suspected_compromised", []) or []),
            weighted_confidence=float(value.get("weighted_confidence", 0.0) or 0.0),
        )
    return value


def _coerce_robustness_result(value):
    if value is None or isinstance(value, RobustnessResult):
        return value
    if isinstance(value, dict):
        return RobustnessResult(
            adversarial_techniques=list(value.get("adversarial_techniques", []) or []),
            anti_static_categories=list(value.get("anti_static_categories", []) or []),
            robustness_score=float(value.get("robustness_score", 0.0) or 0.0),
            anti_static_detected=bool(value.get("anti_static_detected", False)),
            anti_emulator_detected=bool(value.get("anti_emulator_detected", False)),
            obfuscation_detected=bool(value.get("obfuscation_detected", False)),
            reflection_detected=bool(value.get("reflection_detected", False)),
            dynamic_loading_detected=bool(value.get("dynamic_loading_detected", False)),
        )
    return value


def _build_runtime_config(payload: Dict[str, Any]) -> AnalysisRuntimeConfig:
    return AnalysisRuntimeConfig(
        llm_api_key=str(payload.get("llm_api_key") or "").strip(),
        llm_base_url=str(payload.get("llm_base_url") or "").strip(),
        proxy_http=str(payload.get("proxy_http") or "").strip(),
        proxy_https=str(payload.get("proxy_https") or "").strip(),
        proxy_all=str(payload.get("proxy_all") or "").strip(),
        enable_screenshot=str(payload.get("enable_screenshot") or "") in {"on", "true", "1", "yes"},
    )


def _save_uploaded_apk_bundle(files) -> str:
    bundle_dir = Path(tempfile.mkdtemp(prefix="sentinelguard_apk_bundle_"))
    for uploaded in files:
        bundle_path = bundle_dir / Path(uploaded.filename).name
        uploaded.save(bundle_path)
    return str(bundle_dir)


@app.get("/reports/<path:filename>")
def report_file(filename: str):
    return _serve_report(filename, download=False)


@app.get("/reports/<path:filename>/download")
def download_report_file(filename: str):
    return _serve_report(filename, download=True)


def _serve_report(filename: str, download: bool):
    report_dir = Path(settings.DETECTION_REPORT_DIR).resolve()
    target = (report_dir / filename).resolve()
    if report_dir not in target.parents and target != report_dir:
        abort(404)
    if not target.exists():
        abort(404)
    return send_from_directory(report_dir, filename, as_attachment=download)


if __name__ == "__main__":
    app.run(host=settings.HOST, port=settings.PORT, debug=False)