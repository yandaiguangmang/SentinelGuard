from __future__ import annotations

import tempfile
from pathlib import Path

from flask import Flask, abort, render_template, request, send_from_directory

from SentinelGuard.judgement import run_deep_url_detection_from_static, run_detection, run_static_detection
from SentinelGuard.report import save_detection_report
from config import settings

app = Flask(__name__)
app.config["SECRET_KEY"] = "SentinelGuard-URL-Security-Web"
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024


@app.get("/")
def index():
    return render_template("index.html", report=None, error=None, defaults={
        "target": "",
        "target_type": "auto",
        "fetch_page": True,
        "deep": settings.ENABLE_DEEP_ANALYSIS,
    })


@app.post("/analyze")
def analyze():
    target = (request.form.get("target") or "").strip()
    target_type = (request.form.get("target_type") or "auto").strip()
    fetch_page = request.form.get("fetch_page") == "on"
    deep = request.form.get("deep") == "on"

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
        })

    report = run_detection(target, target_type=target_type, fetch_page=fetch_page)
    if deep or settings.ENABLE_DEEP_ANALYSIS:
        try:
            report = run_deep_url_detection_from_static(report, persist_report=False)
        except Exception as exc:
            return render_template("index.html", report=report, error=f"深度研判失败，已返回静态结果：{exc}", defaults={
                "target": target,
                "target_type": target_type,
                "fetch_page": fetch_page,
                "deep": deep,
            })

    report = save_detection_report(report, output_dir=Path(settings.DETECTION_REPORT_DIR))
    return render_template("index.html", report=report, error=None, defaults={
        "target": target,
        "target_type": target_type,
        "fetch_page": fetch_page,
        "deep": deep,
    })


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