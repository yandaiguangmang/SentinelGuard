from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List
from zipfile import BadZipFile, ZipFile

from SentinelGuard.state import APKIR, DetectionFinding


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

    target_ir.apk = apk_ir
    return {"findings": findings, "apk_summary": summary}


def _enrich_apk_ir(apk_ir: APKIR) -> APKIR:
    path = Path(apk_ir.normalized_path)
    if not path.exists():
        return apk_ir

    apk_ir.size_bytes = path.stat().st_size
    apk_ir.sha256 = _sha256_file(path)

    try:
        with ZipFile(path) as archive:
            names = archive.namelist()
            apk_ir.key_files = _collect_key_files(names)
            apk_ir.evidence_summary = _build_evidence_summary(names, archive)
            manifest = _read_manifest_text(archive)
            apk_ir.permissions = _extract_permissions(manifest)
            apk_ir.package_name = _extract_first(manifest, r'package="([^"]+)"')
            apk_ir.version_name = _extract_first(manifest, r'android:versionName="([^"]+)"')
            apk_ir.version_code = _extract_first(manifest, r'android:versionCode="([^"]+)"')
            apk_ir.activities = _extract_components(manifest, "activity")
            apk_ir.services = _extract_components(manifest, "service")
            apk_ir.receivers = _extract_components(manifest, "receiver")
            apk_ir.providers = _extract_components(manifest, "provider")
            apk_ir.extracted_strings = _extract_strings(names, archive)
            apk_ir.certificate_subject, apk_ir.certificate_issuer, apk_ir.certificate_sha256 = _extract_certificate_info(names, archive)
    except BadZipFile:
        return apk_ir

    return apk_ir


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
            "样本文件体积较大，可能包含大量资源、内嵌载荷或混淆内容。",
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
    }


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


def _join_preview(values: Iterable[str], limit: int = 8) -> str:
    items = list(values)
    return "; ".join(items[:limit])


def _collect_key_files(names: List[str]) -> List[str]:
    selected: List[str] = []
    counters = Counter()

    def add_item(label: str, value: str) -> None:
        entry = f"{label}: {value}"
        if entry not in selected:
            selected.append(entry)

    for name in names:
        upper = name.upper()
        lower = name.lower()

        if name in MANIFEST_CANDIDATES:
            add_item("manifest", name)
            counters["manifest"] += 1
            continue

        if upper.startswith(SIGNATURE_PREFIX) and upper.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
            add_item("signature", name)
            counters["signature"] += 1
            continue

        if lower.endswith(".dex"):
            add_item("dex", name)
            counters["dex"] += 1
            continue

        if lower.startswith(("assets/", "res/", "lib/", "smali/")) and lower.endswith(KEY_FILE_EXTENSIONS):
            add_item("resource", name)
            counters["resource"] += 1

    return selected[:60]


def _build_evidence_summary(names: List[str], archive: ZipFile) -> Dict[str, Any]:
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
            summary["manifest_files"].append(_describe_archive_entry(name, archive))
            continue
        if upper.startswith(SIGNATURE_PREFIX) and upper.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
            summary["signature_files"].append(_describe_archive_entry(name, archive))
            continue
        if lower.endswith(".dex"):
            summary["dex_files"].append(_describe_archive_entry(name, archive))
            continue
        if lower.endswith((".so", ".jar", ".aar")):
            summary["native_libraries"].append(_describe_archive_entry(name, archive))
            continue
        if lower.startswith(("assets/", "res/", "smali/")) and lower.endswith(KEY_FILE_EXTENSIONS):
            entry = _describe_archive_entry(name, archive)
            summary["resource_files"].append(entry)
            if lower.endswith((".xml", ".json", ".txt", ".ini", ".cfg", ".conf", ".properties", ".js", ".html", ".htm")):
                preview = _read_text_preview(archive, name)
                if preview:
                    summary["text_previews"].append({"name": name, "preview": preview})
            continue
        if lower.endswith((".xml", ".json", ".txt", ".ini", ".cfg", ".conf", ".properties", ".js", ".html", ".htm")) and (lower.startswith("assets/") or lower.startswith("res/")):
            summary["config_files"].append(_describe_archive_entry(name, archive))

    for key in list(summary.keys()):
        value = summary[key]
        if isinstance(value, list):
            summary[key] = value[:40]

    summary["total_files"] = len(names)
    summary["key_file_count"] = sum(len(summary[k]) for k in ("manifest_files", "signature_files", "dex_files", "resource_files", "native_libraries", "config_files"))
    return summary


def _describe_archive_entry(name: str, archive: ZipFile) -> Dict[str, Any]:
    try:
        info = archive.getinfo(name)
        return {"name": name, "size": info.file_size, "compressed_size": info.compress_size}
    except KeyError:
        return {"name": name, "size": 0, "compressed_size": 0}


def _read_text_preview(archive: ZipFile, name: str, limit: int = 512) -> str:
    try:
        with archive.open(name) as fp:
            data = fp.read(limit)
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _finding(rule_id: str, title: str, severity: str, description: str, evidence: str, recommendation: str) -> DetectionFinding:
    return DetectionFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
    )
