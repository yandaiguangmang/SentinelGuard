from __future__ import annotations

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
)
from SentinelGuard.report import save_detection_report
from SentinelGuard.task_manager import task_manager
from SentinelGuard.state import AnalysisRuntimeConfig
from config import settings

app = Flask(__name__)
app.config["SECRET_KEY"] = "SentinelGuard-URL-Security-Web"
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

logging.getLogger("werkzeug").setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)


@app.get("/")
def index():
    return render_template("index.html", report=None, error=None, defaults={
        "target": "",
        "target_type": "auto",
        "fetch_page": True,
        "llm_api_key": "",
        "llm_base_url": "",
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
    runtime_config = _build_runtime_config(request.form)

    uploaded_apk = request.files.get("apk_file")
    if uploaded_apk and uploaded_apk.filename:
        suffix = Path(uploaded_apk.filename).suffix.lower()
        if suffix == ".apk":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
                uploaded_apk.save(tmp_file.name)
                target = tmp_file.name
                target_type = "apk"
        else:
            return render_template("index.html", report=None, error="请上传 .apk 文件", defaults={
                "target": target,
                "target_type": target_type,
                "fetch_page": fetch_page,
                "deep": deep,
            })

    if not target:
        return render_template("index.html", report=None, error="请输入待检测的 URL 或上传 APK 文件", defaults={
            "target": target,
            "target_type": target_type,
            "fetch_page": fetch_page,
            "deep": deep,
            **runtime_config.to_dict(),
        })

    report = run_detection(target, target_type=target_type, fetch_page=fetch_page, runtime_config=runtime_config)
    if deep:
        try:
            if report.target_ir.target_type == "apk":
                report = run_apk_deep_detection_from_static(report, persist_report=False, runtime_config=runtime_config)
            else:
                report = run_deep_url_detection_from_static(report, persist_report=False, runtime_config=runtime_config)
        except Exception as exc:
            return render_template("index.html", report=report, error=f"深度研判失败，已返回静态结果：{exc}", defaults={
                "target": target,
                "target_type": target_type,
                "fetch_page": fetch_page,
                "deep": deep,
                **runtime_config.to_dict(),
            })

    report = save_detection_report(report, output_dir=Path(settings.DETECTION_REPORT_DIR))
    return render_template("index.html", report=report, error=None, defaults={
        "target": target,
        "target_type": target_type,
        "fetch_page": fetch_page,
        "deep": deep,
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
    deep = str(payload.get("deep") or "") in {"on", "true", "1", "yes"}
    runtime_config = _build_runtime_config(payload)

    uploaded_apk = req.files.get("apk_file") if hasattr(req, "files") else None
    if uploaded_apk and uploaded_apk.filename:
        suffix = Path(uploaded_apk.filename).suffix.lower()
        if suffix != ".apk":
            raise ValueError("请上传 .apk 文件")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
            uploaded_apk.save(tmp_file.name)
            target = tmp_file.name
            target_type = "apk"

    uploaded_path = payload.get("uploaded_path") or ""
    if uploaded_path:
        target = str(uploaded_path).strip()
        target_type = "apk"

    task = task_manager.create(target_type=target_type)
    task_manager.update(task.task_id, status="running", progress=5, stage="received", message="任务已接收，准备开始分析")

    thread = threading.Thread(
        target=_run_analysis_pipeline,
        args=(task.task_id, target, target_type, fetch_page, deep, runtime_config),
        daemon=True,
    )
    thread.start()
    return task


def _run_analysis_pipeline(task_id: str, target: str, target_type: str, fetch_page: bool, deep: bool, runtime_config: AnalysisRuntimeConfig) -> None:
    try:
        task_manager.update(task_id, status="running", progress=10, stage="static", message="正在进行静态分析")
        report = run_detection(target, target_type=target_type, fetch_page=fetch_page, runtime_config=runtime_config)
        task_manager.update(task_id, progress=65, stage="static_done", message="静态分析已完成，正在整理证据")

        if deep:
            progress_callback = lambda stage, message, progress: task_manager.update(  # noqa: E731
                task_id,
                progress=progress,
                stage=stage,
                message=message,
            )

            if report.target_ir.target_type == "apk":
                report = run_apk_deep_detection_from_static(
                    report,
                    persist_report=False,
                    runtime_config=runtime_config,
                    progress_callback=progress_callback,
                )
            else:
                report = run_deep_url_detection_from_static(
                    report,
                    persist_report=False,
                    runtime_config=runtime_config,
                    progress_callback=progress_callback,
                )
            task_manager.update(task_id, progress=94, stage="deep_done", message="深度研判已完成，正在生成报告")
        else:
            task_manager.update(task_id, progress=88, stage="static_only", message="静态分析完成，正在生成报告")

        report = save_detection_report(report, output_dir=Path(settings.DETECTION_REPORT_DIR))
        task_manager.finish(task_id, report.to_dict())
    except Exception as exc:
        task_manager.fail(task_id, str(exc))


def _build_runtime_config(payload: Dict[str, Any]) -> AnalysisRuntimeConfig:
    return AnalysisRuntimeConfig(
        llm_api_key=str(payload.get("llm_api_key") or "").strip(),
        llm_base_url=str(payload.get("llm_base_url") or "").strip(),
        proxy_http=str(payload.get("proxy_http") or "").strip(),
        proxy_https=str(payload.get("proxy_https") or "").strip(),
    )


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