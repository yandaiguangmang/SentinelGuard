from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from zipfile import BadZipFile, ZipFile

from SentinelGuard.report import _deduplicate_semantic_findings
from SentinelGuard.state import APKIR, DetectionFinding
from .apk_graph_extractor import APKGraphExtractor

try:  # pragma: no cover - optional dependency fallback
    from androguard.core.apk import APK
except Exception:  # pragma: no cover - dependency fallback
    try:
        # androguard==3.3.5 uses the legacy module path.
        from androguard.core.bytecodes.apk import APK
    except Exception:  # pragma: no cover - dependency fallback
        APK = None


SUSPICIOUS_PERMISSION_KEYWORDS = (
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "QUERY_ALL_PACKAGES",
    "MANAGE_EXTERNAL_STORAGE",
)

SUSPICIOUS_STRING_KEYWORDS = (
    "http://",
    "https://",
    "shell",
    "su",
    "chmod",
    "wget",
    "curl",
    "dexClassLoader",
    "Runtime.getRuntime",
    "TelephonyManager",
    "SmsManager",
    "AccessibilityService",
)

SUSPICIOUS_COMPONENT_KEYWORDS = (
    "BootReceiver",
    "AdminReceiver",
    "AccessibilityService",
    "DeviceAdminReceiver",
    "JobService",
)

KEY_FILE_EXTENSIONS = (
    ".xml",
    ".json",
    ".txt",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".js",
    ".html",
    ".htm",
    ".smali",
)

MANIFEST_CANDIDATES = (
    "AndroidManifest.xml",
    "manifest/AndroidManifest.xml",
)

SIGNATURE_PREFIX = "META-INF/"


def analyze_apk(target_ir) -> Dict[str, Any]:
    if target_ir.target_type != "apk" or not target_ir.apk:
        return {"findings": [], "apk_summary": {}}

    apk_ir = _enrich_apk_ir(target_ir.apk)
    findings = _analyze_apk_ir(apk_ir)
    summary = _build_apk_summary(apk_ir, findings)

    findings = _deduplicate_semantic_findings(findings)
    target_ir.apk = apk_ir
    return {"findings": findings, "apk_summary": summary}


def _enrich_apk_ir(apk_ir: APKIR) -> APKIR:
    path = Path(apk_ir.normalized_path)
    if not path.exists():
        return apk_ir

    apk_ir.size_bytes = path.stat().st_size
    apk_ir.sha256 = _sha256_file(path)

    if APK is not None:
        try:
            return _enrich_with_androguard(apk_ir, path)
        except Exception:
            pass

    try:
        return _enrich_with_zip_fallback(apk_ir, path)
    except BadZipFile:
        return apk_ir


def _enrich_with_androguard(apk_ir: APKIR, path: Path) -> APKIR:
    apk = APK(str(path))

    apk_ir.package_name = apk.get_package() or apk_ir.package_name
    apk_ir.version_name = apk.get_androidversion_name() or apk_ir.version_name
    apk_ir.version_code = str(apk.get_androidversion_code() or apk_ir.version_code or "")
    apk_ir.permissions = sorted(set(apk.get_permissions() or []))
    apk_ir.activities = sorted(set(apk.get_activities() or []))
    apk_ir.services = sorted(set(apk.get_services() or []))
    apk_ir.receivers = sorted(set(apk.get_receivers() or []))
    apk_ir.providers = sorted(set(apk.get_providers() or []))
    apk_ir.certificate_subject, apk_ir.certificate_issuer, apk_ir.certificate_sha256 = _extract_androguard_certificate_info(apk)

    try:
        raw = apk.get_all_dex()
        apk_ir.extracted_strings = _extract_strings_from_dex(raw)
    except Exception:
        apk_ir.extracted_strings = apk_ir.extracted_strings

    try:
        apk_ir.key_files = _collect_key_files(apk.get_files())
        apk_ir.evidence_summary = _build_evidence_summary(apk.get_files(), None)
    except Exception:
        apk_ir.key_files = apk_ir.key_files

    _attach_graph_data(apk_ir, apk)

    return apk_ir


def _enrich_with_zip_fallback(apk_ir: APKIR, path: Path) -> APKIR:
    try:
        with ZipFile(path) as archive:
            names = archive.namelist()
            apk_ir.key_files = _collect_key_files(names)
            apk_ir.evidence_summary = _build_evidence_summary(names, archive)
            manifest = _read_manifest_text(archive)
            apk_ir.permissions = _extract_permissions(manifest)
            apk_ir.package_name = _extract_first(manifest, r'package="([^"]+)"') or apk_ir.package_name
            apk_ir.version_name = _extract_first(manifest, r'android:versionName="([^"]+)"') or apk_ir.version_name
            apk_ir.version_code = _extract_first(manifest, r'android:versionCode="([^"]+)"') or apk_ir.version_code
            apk_ir.activities = _extract_components(manifest, "activity")
            apk_ir.services = _extract_components(manifest, "service")
            apk_ir.receivers = _extract_components(manifest, "receiver")
            apk_ir.providers = _extract_components(manifest, "provider")
            apk_ir.extracted_strings = _extract_strings(names, archive)
            apk_ir.certificate_subject, apk_ir.certificate_issuer, apk_ir.certificate_sha256 = _extract_certificate_info(names, archive)
    except BadZipFile:
        return apk_ir
    return apk_ir


def _extract_androguard_certificate_info(apk: Any) -> tuple[str, str, str]:
    try:
        cert = apk.get_certificates()[0]
    except Exception:
        return "", "", ""

    subject = ""
    issuer = ""
    digest = ""
    try:
        subject = str(cert.subject) if cert.subject else ""
    except Exception:
        pass
    try:
        issuer = str(cert.issuer) if cert.issuer else ""
    except Exception:
        pass
    try:
        digest = hashlib.sha256(cert.public_bytes()).hexdigest()
    except Exception:
        try:
            digest = hashlib.sha256(bytes(cert)).hexdigest()
        except Exception:
            digest = ""
    return subject, issuer, digest


def _extract_strings_from_dex(raw_dex: List[bytes]) -> List[str]:
    strings: List[str] = []
    for dex_bytes in raw_dex or []:
        if not dex_bytes:
            continue
        for candidate in re.findall(rb"[\x20-\x7e]{6,}", dex_bytes):
            text = candidate.decode("utf-8", errors="ignore")
            if text and text not in strings:
                strings.append(text)
            if len(strings) >= 80:
                return strings
    return strings


def _analyze_apk_ir(apk_ir: APKIR) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []

    if apk_ir.key_files:
        findings.append(_finding(
            "APK_KEY_FILES_REVIEWED",
            "关键文件证据已提取",
            "low",
            "已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。",
            _join_preview(apk_ir.key_files, limit=12),
            "结合 manifest、资源、签名与代码文件继续确认风险链条。",
        ))

    if not apk_ir.package_name:
        findings.append(_finding(
            "APK_MISSING_PACKAGE",
            "未解析到包名",
            "medium",
            "APK 中未能提取出明确的包名，样本身份不够清晰。",
            apk_ir.file_name,
            "补充样本来源与签名信息后再复核。",
        ))

    if apk_ir.size_bytes >= 500 * 1024 * 1024:
        findings.append(_finding(
            "APK_LARGE_SIZE",
            "安装包体积异常偏大",
            "low",
            f"样本文件体积较大，可能包含大量资源、内嵌载荷或混淆内容。",
            f"{apk_ir.size_bytes} bytes",
            "结合资源目录与字符串内容继续检查。",
        ))

    permission_hits = [perm for perm in apk_ir.permissions if any(keyword in perm for keyword in SUSPICIOUS_PERMISSION_KEYWORDS)]
    if permission_hits:
        findings.append(_finding(
            "APK_SUSPICIOUS_PERMISSION",
            "存在敏感权限请求",
            "high",
            "安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。",
            ", ".join(permission_hits[:10]),
            "确认权限是否与业务功能一致，避免授予不必要权限。",
        ))

    if apk_ir.certificate_subject and apk_ir.certificate_issuer and apk_ir.certificate_subject != apk_ir.certificate_issuer:
        findings.append(_finding(
            "APK_SIGNING_INFO",
            "签名证书信息需复核",
            "low",
            "签名主体与颁发者信息不完全一致，建议结合来源进一步核验。",
            f"Subject={apk_ir.certificate_subject}; Issuer={apk_ir.certificate_issuer}",
            "核对签名证书是否符合官方发布习惯。",
        ))

    string_hits = [text for text in apk_ir.extracted_strings if any(keyword.lower() in text.lower() for keyword in SUSPICIOUS_STRING_KEYWORDS)]
    if string_hits:
        findings.append(_finding(
            "APK_SUSPICIOUS_STRINGS",
            "存在可疑字符串线索",
            "medium",
            "样本中出现命令执行、远程地址或系统调用相关字符串。",
            _join_preview(string_hits),
            "结合反编译结果确认这些字符串是否参与实际行为。",
        ))

    component_hits = []
    for bucket in (apk_ir.activities, apk_ir.services, apk_ir.receivers, apk_ir.providers):
        component_hits.extend([name for name in bucket if any(keyword.lower() in name.lower() for keyword in SUSPICIOUS_COMPONENT_KEYWORDS)])
    if component_hits:
        findings.append(_finding(
            "APK_PERSISTENT_COMPONENTS",
            "存在持久化或高权限组件线索",
            "medium",
            "组件名称显示可能存在开机自启、管理器或辅助功能相关入口。",
            _join_preview(component_hits),
            "检查这些组件是否会在后台持续运行或触发敏感动作。",
        ))

    if not findings:
        findings.append(_finding(
            "APK_BASELINE",
            "未命中明显高危特征",
            "low",
            "当前规则未发现明显异常，但仍需要结合样本来源与外部信誉复核。",
            apk_ir.file_name,
            "建议继续查看包名、签名与权限是否符合预期。",
        ))

    return findings


def _build_apk_summary(apk_ir: APKIR, findings: List[DetectionFinding]) -> Dict[str, Any]:
    graph_data = apk_ir.graph_data or {}
    graph_stats = graph_data.get("stats", {}) if isinstance(graph_data, dict) else {}
    api_graph = graph_data.get("api_graph", {}) if isinstance(graph_data, dict) else {}
    return {
        "file_name": apk_ir.file_name,
        "package_name": apk_ir.package_name,
        "version_name": apk_ir.version_name,
        "version_code": apk_ir.version_code,
        "sha256": apk_ir.sha256,
        "size_bytes": apk_ir.size_bytes,
        "permission_count": len(apk_ir.permissions),
        "component_count": sum(len(bucket) for bucket in (apk_ir.activities, apk_ir.services, apk_ir.receivers, apk_ir.providers)),
        "finding_count": len(findings),
        "key_file_count": len(apk_ir.key_files),
        "evidence_summary": apk_ir.evidence_summary,
        "graph_summary": {
            "cfg_node_count": graph_stats.get("cfg_node_count", 0),
            "cfg_edge_count": graph_stats.get("cfg_edge_count", 0),
            "fcg_node_count": graph_stats.get("fcg_node_count", 0),
            "fcg_edge_count": graph_stats.get("fcg_edge_count", 0),
            "api_graph_node_count": graph_stats.get("api_graph_node_count", 0),
            "api_graph_edge_count": graph_stats.get("api_graph_edge_count", 0),
            "api_call_type_count": graph_stats.get("api_call_type_count", 0),
            "api_call_count": sum((api_graph.get("api_call_counts", {}) or {}).values()) if isinstance(api_graph, dict) else 0,
            "total_node_count": graph_stats.get("total_node_count", 0),
            "total_edge_count": graph_stats.get("total_edge_count", 0),
            "density": graph_stats.get("density", 0.0),
            "average_degree": graph_stats.get("average_degree", 0.0),
            "has_fallback": graph_stats.get("has_fallback", False),
        },
        "graph_warnings": (graph_data.get("warnings", []) if isinstance(graph_data, dict) else []),
    }


def _attach_graph_data(apk_ir: APKIR, apk: Any) -> None:
    warnings: List[str] = []
    try:
        extractor = APKGraphExtractor()
        # 直接传入 APK 对象，兼容 androguard==3.3.5 的 get_dex()/get_all_dex()
        # 以及 extractor 内部基于 APK.get_dex() 的归一化逻辑。
        graph_result = extractor.extract_all(apk, {
            "file_name": apk_ir.file_name,
            "package_name": apk_ir.package_name,
            "api_file_count": len(list(apk.get_all_dex() or [])) if hasattr(apk, "get_all_dex") else 0,
        })
        apk_ir.graph_data = graph_result
    except Exception as exc:
        warnings.append(f"图结构提取失败：{exc}")
        apk_ir.graph_data = None

    if warnings:
        evidence_summary = apk_ir.evidence_summary if isinstance(apk_ir.evidence_summary, dict) else {}
        existing = list(evidence_summary.get("warnings", [])) if isinstance(evidence_summary.get("warnings"), list) else []
        existing.extend(warnings)
        evidence_summary["warnings"] = existing
        apk_ir.evidence_summary = evidence_summary


def _read_manifest_text(archive: ZipFile) -> str:
    for candidate in ("AndroidManifest.xml", "manifest/AndroidManifest.xml"):
        try:
            with archive.open(candidate) as fp:
                data = fp.read()
                return data.decode("utf-8", errors="ignore")
        except KeyError:
            continue
    return ""


def _extract_permissions(manifest: str) -> List[str]:
    return sorted(set(re.findall(r'android:name="([^"]+)"', manifest)))


def _extract_components(manifest: str, tag: str) -> List[str]:
    pattern = rf'<{tag}[^>]*android:name="([^"]+)"'
    return sorted(set(re.findall(pattern, manifest)))


def _extract_first(text: str, pattern: str) -> str:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""


def _extract_strings(names: List[str], archive: ZipFile) -> List[str]:
    strings: List[str] = []
    for name in names:
        if name.endswith((".xml", ".txt", ".json", ".js", ".smali", ".properties")):
            try:
                with archive.open(name) as fp:
                    text = fp.read().decode("utf-8", errors="ignore")
                for candidate in re.findall(r"[\w:\./@-]{6,}", text):
                    if candidate not in strings:
                        strings.append(candidate)
                    if len(strings) >= 80:
                        return strings
            except Exception:
                continue
    return strings


def _extract_certificate_info(names: List[str], archive: ZipFile) -> tuple[str, str, str]:
    for name in names:
        upper = name.upper()
        if upper.startswith(SIGNATURE_PREFIX) and upper.endswith((".RSA", ".DSA", ".EC")):
            try:
                with archive.open(name) as fp:
                    data = fp.read()
                digest = hashlib.sha256(data).hexdigest()
                return ("", "", digest)
            except Exception:
                return ("", "", "")
    return ("", "", "")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _join_preview(values: Any, limit: int = 8) -> str:
    items = list(values)
    return "; ".join(items[:limit])


def _collect_key_files(names: List[str]) -> List[str]:
    selected: List[str] = []

    def add_item(label: str, value: str) -> None:
        entry = f"{label}: {value}"
        if entry not in selected:
            selected.append(entry)

    for name in names:
        upper = name.upper()
        lower = name.lower()

        if name in MANIFEST_CANDIDATES:
            add_item("manifest", name)
            continue

        if upper.startswith(SIGNATURE_PREFIX) and upper.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
            add_item("signature", name)
            continue

        if lower.endswith(".dex"):
            add_item("dex", name)
            continue

        if lower.startswith(("assets/", "res/", "lib/", "smali/")) and lower.endswith(KEY_FILE_EXTENSIONS):
            add_item("resource", name)

    return selected[:60]


def _build_evidence_summary(names: List[str], archive: ZipFile | None) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "manifest_files": [],
        "signature_files": [],
        "dex_files": [],
        "resource_files": [],
        "native_libraries": [],
        "config_files": [],
        "text_previews": [],
    }

    for name in names:
        lower = name.lower()
        upper = name.upper()

        if name in MANIFEST_CANDIDATES:
            summary["manifest_files"].append({"name": name})
            continue
        if upper.startswith(SIGNATURE_PREFIX) and upper.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
            summary["signature_files"].append({"name": name})
            continue
        if lower.endswith(".dex"):
            summary["dex_files"].append({"name": name})
            continue
        if lower.endswith((".so", ".jar", ".aar")):
            summary["native_libraries"].append({"name": name})
            continue
        if lower.startswith(("assets/", "res/", "smali/")) and lower.endswith(KEY_FILE_EXTENSIONS):
            summary["resource_files"].append({"name": name})
            continue
        if lower.endswith((".xml", ".json", ".txt", ".ini", ".cfg", ".conf", ".properties", ".js", ".html", ".htm")) and (lower.startswith("assets/") or lower.startswith("res/")):
            summary["config_files"].append({"name": name})

    if archive is not None:
        for key in list(summary.keys()):
            value = summary[key]
            if isinstance(value, list):
                summary[key] = value[:40]
        summary["total_files"] = len(names)
        summary["key_file_count"] = sum(len(summary[k]) for k in ("manifest_files", "signature_files", "dex_files", "resource_files", "native_libraries", "config_files"))
    return summary


def _finding(rule_id: str, title: str, severity: str, description: str, evidence: str, recommendation: str) -> DetectionFinding:
    return DetectionFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
    )
