from __future__ import annotations

import hashlib
from collections import defaultdict
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zipfile import BadZipFile, ZipFile

from SentinelGuard.report import _deduplicate_semantic_findings
from SentinelGuard.state import APKIR, DetectionFinding, GraphStructure
from .apk_graph_extractor import APKGraphExtractor
from .apk_rules import (
    DANGEROUS_API_RULES,
    KEY_FILE_EXTENSIONS,
    MANIFEST_CANDIDATES,
    PERMISSION_RISK_LEVEL,
    MALICIOUS_BEHAVIOR_KEYWORDS,
    SUSPICIOUS_COMPONENT_KEYWORDS,
    SUSPICIOUS_PERMISSION_KEYWORDS,
    SUSPICIOUS_STRING_KEYWORDS,
    SIGNATURE_PREFIX,
    check_suspicious_file_paths,
    check_suspicious_package,
    match_dangerous_api,
    match_malicious_behavior,
)

try:  # pragma: no cover - optional dependency fallback
    from androguard.core.apk import APK
except Exception:  # pragma: no cover - dependency fallback
    try:
        # androguard==3.3.5 uses the legacy module path.
        from androguard.core.bytecodes.apk import APK
    except Exception:  # pragma: no cover - dependency fallback
        APK = None



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
        except BadZipFile:
            _attach_graph_fallback(apk_ir, "BadZipFile: File is not a zip file")
            return apk_ir
        except Exception as exc:
            # androguard 解析失败时，保留 zip fallback 继续尝试；
            # 若 zip 也失败，则在 fallback 路径中显式标记图结构回退。
            last_androguard_error = exc
    else:
        last_androguard_error = None

    try:
        return _enrich_with_zip_fallback(apk_ir, path)
    except BadZipFile:
        reason = "BadZipFile: File is not a zip file"
        if 'last_androguard_error' in locals() and last_androguard_error is not None:
            reason = f"{type(last_androguard_error).__name__}: {last_androguard_error}; {reason}"
        _attach_graph_fallback(apk_ir, reason)
        return apk_ir


def _enrich_with_androguard(apk_ir: APKIR, path: Path) -> APKIR:
    import time
    print(f"[TIMING] 开始分析: {path.name}")
    t0 = time.time()
    apk = APK(str(path))
    print(f"[TIMING] APK加载完成: {time.time() - t0:.2f}s")
    print(f"[TIMING] 开始提取基础信息 (包名、版本、权限、组件等)")
    t_basic_start = time.time()

    apk_ir.package_name = apk.get_package() or apk_ir.package_name
    apk_ir.version_name = apk.get_androidversion_name() or apk_ir.version_name
    apk_ir.version_code = str(apk.get_androidversion_code() or apk_ir.version_code or "")
    apk_ir.permissions = sorted(set(apk.get_permissions() or []))
    apk_ir.activities = sorted(set(apk.get_activities() or []))
    apk_ir.services = sorted(set(apk.get_services() or []))
    apk_ir.receivers = sorted(set(apk.get_receivers() or []))
    apk_ir.providers = sorted(set(apk.get_providers() or []))
    apk_ir.certificate_subject, apk_ir.certificate_issuer, apk_ir.certificate_sha256 = _extract_androguard_certificate_info(apk)
    print(f"[TIMING] 基础信息提取完成，耗时: {time.time() - t_basic_start:.2f}s")
    print(f"    - 包名: {apk_ir.package_name}")
    print(f"    - 权限数: {len(apk_ir.permissions)}")
    print(f"    - 组件数: {len(apk_ir.activities) + len(apk_ir.services) + len(apk_ir.receivers) + len(apk_ir.providers)}")

    print(f"[TIMING] 开始提取 DEX 字符串")
    t_dex_start = time.time()
    try:
        print(f"[TIMING] 调用 apk.get_all_dex()...")
        raw = apk.get_all_dex()
        print(f"[TIMING] apk.get_all_dex() 完成，耗时: {time.time() - t_dex_start:.2f}s")
        simple_dex_strings = _extract_strings_from_dex(raw)
        dex_strings: List[Dict[str, Any]] = []
        for dex_bytes in raw or []:
            if dex_bytes:
                dex_strings.extend(_extract_dex_strings_enhanced(dex_bytes, max_strings=80))
        print(f"[TIMING] DEX 字符串提取完成，耗时: {time.time() - t_dex_start:.2f}s")
        # 保持 extracted_strings 为简单字符串列表（深度研判兼容）
        apk_ir.extracted_strings = [item["text"] for item in dex_strings if item.get("text")]
        if not apk_ir.extracted_strings:
            apk_ir.extracted_strings = simple_dex_strings
        # 新增：带上下文的字符串（仅静态分析增强使用）
        apk_ir._strings_with_context = dex_strings
        print(f"    - 提取 DEX 字符串数: {len(apk_ir.extracted_strings)}")
    except Exception:
        apk_ir.extracted_strings = apk_ir.extracted_strings
        print("error: DEX 字符串提取失败，可能存在异常 DEX 文件或解析错误。")

        print(f"[TIMING] 开始收集关键文件")
        t_files_start = time.time()
    try:
        apk_ir.key_files = _collect_key_files(apk.get_files())
        apk_ir.evidence_summary = _build_evidence_summary(apk.get_files(), None)
        print(f"[TIMING] 关键文件收集完成，耗时: {time.time() - t_files_start:.2f}s")
        print(f"    - 关键文件数: {len(apk_ir.key_files)}")
    except Exception:
        apk_ir.key_files = apk_ir.key_files
        print("error: 关键文件提取失败，可能存在异常 APK 文件或解析错误。")

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
            # 增强：提取带上下文的字符串
            strings_with_context = _extract_strings_with_context(apk_ir, archive)
            # 保持 extracted_strings 为简单字符串列表
            apk_ir.extracted_strings = [item["text"] for item in strings_with_context if item.get("text")]
            # 新增：带上下文的字符串
            apk_ir._strings_with_context = strings_with_context
    except BadZipFile:
        _attach_graph_fallback(apk_ir, "BadZipFile: File is not a zip file")
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


def _extract_dex_strings_enhanced(dex_bytes: bytes, max_strings: int = 200) -> List[Dict[str, Any]]:
    """
    从 DEX 字节码中提取更多有价值的字符串和上下文信息。
    返回包含字符串、上下文类型和上下文的字典列表。
    """
    results: List[Dict[str, Any]] = []

    if not dex_bytes:
        return results

    CHUNK_SIZE = 4096
    OVERLAP = 256

    for i in range(0, len(dex_bytes), CHUNK_SIZE - OVERLAP):
        chunk = dex_bytes[i:i + CHUNK_SIZE]

        for match in re.finditer(rb'[\x20-\x7e]{4,}', chunk):
            text = match.group().decode('utf-8', errors='ignore')
            if len(results) >= max_strings:
                return results

            if re.match(r'^[\d\s\-_]+$', text):
                continue

            start = max(0, match.start() - 50)
            end = min(len(chunk), match.end() + 50)
            context = chunk[start:end].decode('utf-8', errors='ignore')

            string_type = _classify_string_type(text)

            results.append({
                "text": text,
                "type": string_type,
                "context": context[:200],
                "offset": i + match.start(),
            })

    return results


def _classify_string_type(text: str) -> str:
    """分类字符串类型"""
    text_lower = text.lower()

    if re.match(r'^https?://', text_lower):
        return "url"
    if re.match(r'^[a-z0-9\-]+(\.[a-z0-9\-]+)+', text_lower) and '.' in text:
        return "domain"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text):
        return "ip_address"
    if re.match(r'^/(?:[a-zA-Z0-9_\-./]+)+$', text):
        return "file_path"
    if ';->' in text or text.startswith('L') and ';' in text:
        return "method_signature"
    if re.match(r'^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$', text_lower):
        return "package"
    if any(kw in text_lower for kw in ['key', 'secret', 'token', 'password', 'passwd', 'auth']):
        return "sensitive_data"
    if any(kw in text_lower for kw in ['exec', 'cmd', 'shell', 'su', 'chmod', 'rm', 'cp', 'mv']):
        return "command"

    return "unknown"


def _extract_strings_with_context(apk_ir: APKIR, archive: Optional[ZipFile] = None) -> List[Dict[str, Any]]:
    """从 APK 中提取带有上下文的字符串"""
    all_strings: List[Dict[str, Any]] = []
    seen_texts: set[str] = set()

    if apk_ir.extracted_strings:
        for text in apk_ir.extracted_strings[:100]:
            if text not in seen_texts:
                seen_texts.add(text)
                all_strings.append({
                    "text": text,
                    "type": _classify_string_type(text),
                    "context": text[:200],
                    "source": "dex",
                })

    if archive is not None:
        file_extensions = ('.xml', '.json', '.txt', '.ini', '.cfg', '.conf', '.properties', '.js', '.html', '.htm')
        max_files = 20

        for idx, name in enumerate(archive.namelist()):
            if idx >= max_files:
                break
            if any(name.lower().endswith(ext) for ext in file_extensions):
                try:
                    with archive.open(name) as fp:
                        content = fp.read().decode('utf-8', errors='ignore')
                    for match in re.finditer(r'[\w:/@\.\-_]{6,}', content):
                        text = match.group()
                        if text not in seen_texts and len(seen_texts) < 200:
                            seen_texts.add(text)
                            all_strings.append({
                                "text": text,
                                "type": _classify_string_type(text),
                                "context": content[max(0, match.start()-50):min(len(content), match.end()+50)][:200],
                                "source": name,
                            })
                except Exception:
                    continue

    return all_strings[:200]


def _match_dangerous_apis(strings_with_context: List[Dict[str, Any]]) -> List[DetectionFinding]:
    """匹配危险 API"""
    findings: List[DetectionFinding] = []
    matched: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for item in strings_with_context:
        text = item.get("text", "")
        matches = match_dangerous_api(text)
        for category, api, severity in matches:
            matched[category].append({
                "api": api,
                "context": item.get("context", "")[:150],
                "severity": severity,
            })

    for category, items in matched.items():
        if not items:
            continue

        critical_items = [i for i in items if i["severity"] == "critical"]
        high_items = [i for i in items if i["severity"] == "high"]

        if critical_items:
            severity = "critical"
            evidence = "; ".join([f"{i['api']}" for i in critical_items[:5]])
        elif high_items:
            severity = "high"
            evidence = "; ".join([f"{i['api']}" for i in high_items[:5]])
        else:
            severity = "medium"
            evidence = "; ".join([f"{i['api']}" for i in items[:5]])

        description = _get_category_description(category)

        findings.append(DetectionFinding(
            rule_id=f"APK_DANGEROUS_API_{category.upper()}",
            title=f"检测到 {_get_category_label(category)} API 调用",
            severity=severity,
            description=description,
            evidence=f"类别: {category}, 匹配: {evidence}",
            recommendation="建议结合反编译结果确认这些 API 是否被实际调用，以及调用上下文是否合理。",
        ))

    return findings


def _match_malicious_behaviors(strings_with_context: List[Dict[str, Any]]) -> List[DetectionFinding]:
    """匹配恶意行为关键词"""
    findings: List[DetectionFinding] = []
    behavior_matches: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    for item in strings_with_context:
        text = item.get("text", "")
        matches = match_malicious_behavior(text)
        for behavior, keyword, severity in matches:
            behavior_matches[behavior].append((keyword, severity))

    for behavior, matches in behavior_matches.items():
        if not matches:
            continue

        severities = [s for _, s in matches]
        if "critical" in severities:
            severity = "critical"
        elif "high" in severities:
            severity = "high"
        elif "medium" in severities:
            severity = "medium"
        else:
            severity = "low"

        keywords = list(set([k for k, _ in matches]))[:5]

        findings.append(DetectionFinding(
            rule_id=f"APK_MALICIOUS_BEHAVIOR_{behavior.upper()}",
            title=f"检测到恶意行为模式: {_get_behavior_label(behavior)}",
            severity=severity,
            description=f"在 APK 中检测到 {_get_behavior_label(behavior)} 相关的关键词。",
            evidence=f"行为类型: {behavior}, 关键词: {', '.join(keywords)}",
            recommendation=f"建议深入分析该行为的实现代码，确认是否真正存在 {_get_behavior_label(behavior)} 功能。",
        ))

    return findings


def _check_package_name(apk_ir: APKIR) -> List[DetectionFinding]:
    """检查包名是否可疑"""
    findings: List[DetectionFinding] = []
    package_name = apk_ir.package_name

    if not package_name:
        return findings

    suspicious = check_suspicious_package(package_name)
    if suspicious:
        reasons = [reason for _, reason in suspicious]
        findings.append(DetectionFinding(
            rule_id="APK_SUSPICIOUS_PACKAGE",
            title="包名疑似自动生成或仿冒",
            severity="high",
            description=f"包名 '{package_name}' 符合可疑模式: {', '.join(reasons)}",
            evidence=f"包名: {package_name}",
            recommendation="建议核实该包名是否与官方应用一致，是否存在仿冒知名应用的可能。",
        ))

    return findings


def _check_file_paths(apk_ir: APKIR) -> List[DetectionFinding]:
    """检查文件路径是否可疑"""
    findings: List[DetectionFinding] = []

    if not apk_ir.key_files:
        return findings

    suspicious_files = check_suspicious_file_paths(apk_ir.key_files)
    if suspicious_files:
        evidence = "; ".join([f"{fname}" for fname, _, _ in suspicious_files[:5]])
        findings.append(DetectionFinding(
            rule_id="APK_SUSPICIOUS_FILE_PATHS",
            title="发现可疑文件路径",
            severity="medium",
            description="APK 中存在可疑的文件路径模式，可能包含隐藏的可执行文件或配置。",
            evidence=evidence,
            recommendation="建议检查这些文件的内容，确认是否包含恶意载荷或敏感配置。",
        ))

    return findings


def _check_permission_combinations(apk_ir: APKIR) -> List[DetectionFinding]:
    """检查权限组合是否可疑"""
    findings: List[DetectionFinding] = []

    if not apk_ir.permissions:
        return findings

    high_risk_perms = []
    for perm in apk_ir.permissions:
        perm_name = perm.split('.')[-1] if '.' in perm else perm
        if perm_name in PERMISSION_RISK_LEVEL:
            level = PERMISSION_RISK_LEVEL[perm_name]
            if level in ("critical", "high"):
                high_risk_perms.append((perm_name, level))

    if not high_risk_perms:
        return findings

    critical_perms = [p for p, l in high_risk_perms if l == "critical"]
    high_perms = [p for p, l in high_risk_perms if l == "high"]

    if len(critical_perms) >= 2:
        findings.append(DetectionFinding(
            rule_id="APK_PERMISSION_COMBINATION_CRITICAL",
            title="检测到多个关键权限组合",
            severity="critical",
            description=f"APK 请求了 {len(critical_perms)} 个关键权限: {', '.join(critical_perms[:5])}。",
            evidence=f"关键权限: {', '.join(critical_perms[:8])}",
            recommendation="建议仔细审查这些权限的实际使用场景，确认是否与应用功能匹配。",
        ))

    sms_perms = [p for p in high_risk_perms if p[0] in ("READ_SMS", "SEND_SMS", "RECEIVE_SMS")]
    phone_perms = [p for p in high_risk_perms if p[0] in ("READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS")]
    location_perms = [p for p in high_risk_perms if p[0] in ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION")]

    if sms_perms and phone_perms and location_perms:
        findings.append(DetectionFinding(
            rule_id="APK_PERMISSION_COMBINATION_SMS_PHONE_LOCATION",
            title="检测到短信+电话+位置权限组合",
            severity="critical",
            description="APK 同时请求了短信、电话和位置相关权限，这是典型的恶意应用行为模式。",
            evidence=f"短信权限: {', '.join([p[0] for p in sms_perms])}; 电话权限: {', '.join([p[0] for p in phone_perms])}; 位置权限: {', '.join([p[0] for p in location_perms])}",
            recommendation="建议重点关注该应用的隐私数据访问行为，确认是否存在数据外泄风险。",
        ))

    system_perms = [p for p in high_risk_perms if p[0] in ("REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "INSTALL_PACKAGES", "DELETE_PACKAGES")]
    if len(system_perms) >= 2:
        findings.append(DetectionFinding(
            rule_id="APK_PERMISSION_COMBINATION_SYSTEM",
            title="检测到系统管理权限组合",
            severity="high",
            description=f"APK 请求了多个系统管理权限: {', '.join([p[0] for p in system_perms])}。",
            evidence=f"系统权限: {', '.join([p[0] for p in system_perms])}",
            recommendation="建议确认该应用是否需要这些权限，警惕可能的提权或恶意操作。",
        ))

    return findings


def _match_string_patterns(strings_with_context: List[Dict[str, Any]]) -> List[DetectionFinding]:
    """匹配可疑字符串模式"""
    findings: List[DetectionFinding] = []

    urls = []
    domains = []
    ip_addresses = []
    sensitive_data = []
    commands = []

    for item in strings_with_context:
        text = item.get("text", "")
        string_type = item.get("type", "unknown")

        if string_type == "url":
            urls.append(text)
        elif string_type == "domain":
            domains.append(text)
        elif string_type == "ip_address":
            ip_addresses.append(text)
        elif string_type == "sensitive_data":
            sensitive_data.append(text)
        elif string_type == "command":
            commands.append(text)

    if urls:
        suspicious_urls = [u for u in urls if any(p in u.lower() for p in ['/admin', '/login', '/api', '/upload', '/download', '/cmd', '/exec'])]
        if suspicious_urls:
            findings.append(DetectionFinding(
                rule_id="APK_SUSPICIOUS_URLS",
                title="发现可疑 URL",
                severity="medium",
                description=f"在 APK 中发现 {len(suspicious_urls)} 个可疑 URL 地址。",
                evidence="; ".join(suspicious_urls[:5]),
                recommendation="建议检查这些 URL 的访问记录，确认是否被实际使用。",
            ))

    if sensitive_data:
        filtered = [s for s in sensitive_data if len(s) >= 8]
        if filtered:
            findings.append(DetectionFinding(
                rule_id="APK_SENSITIVE_DATA_STRINGS",
                title="发现敏感数据字符串",
                severity="high",
                description="在 APK 中检测到可能包含密钥、密码或认证信息的字符串。",
                evidence="; ".join(filtered[:5]),
                recommendation="建议确认这些字符串是否为硬编码的密钥或密码。",
            ))

    if commands:
        dangerous_commands = [c for c in commands if any(kw in c.lower() for kw in ['rm', 'chmod', 'mount', 'kill', 'ps'])]
        if dangerous_commands:
            findings.append(DetectionFinding(
                rule_id="APK_DANGEROUS_COMMANDS",
                title="发现危险命令",
                severity="high",
                description="在 APK 中检测到可能用于系统操作的危险命令。",
                evidence="; ".join(dangerous_commands[:5]),
                recommendation="建议检查这些命令是否会被执行。",
            ))

    return findings


def _get_category_label(category: str) -> str:
    labels = {
        "privacy_leak": "隐私窃取",
        "file_operation": "文件操作",
        "network": "网络通信",
        "code_execution": "代码执行",
        "reflection": "反射调用",
        "crypto": "加密操作",
        "system_command": "系统命令",
        "dynamic_loading": "动态加载",
        "persistence": "持久化",
        "payment": "支付相关",
    }
    return labels.get(category, category)


def _get_category_description(category: str) -> str:
    descriptions = {
        "privacy_leak": "检测到与隐私数据获取相关的 API 调用，可能用于收集用户敏感信息。",
        "file_operation": "检测到文件操作相关的 API 调用，可能用于读写或删除文件。",
        "network": "检测到网络通信相关的 API 调用，可能用于外联通信或数据外泄。",
        "code_execution": "检测到代码执行相关的 API 调用，可能用于动态执行代码或命令。",
        "reflection": "检测到反射相关的 API 调用，可能用于绕过静态检测或动态加载代码。",
        "crypto": "检测到加密相关的 API 调用，可能用于数据加密或解密。",
        "system_command": "检测到系统命令相关的 API 调用，可能用于执行系统操作。",
        "dynamic_loading": "检测到动态加载相关的 API 调用，可能用于运行时加载代码。",
        "persistence": "检测到持久化相关的组件，可能用于开机自启或后台运行。",
        "payment": "检测到支付相关的 API 调用，可能用于支付操作或支付欺诈。",
    }
    return descriptions.get(category, f"检测到 {category} 相关的 API 调用。")


def _get_behavior_label(behavior: str) -> str:
    labels = {
        "root_attempt": "Root 尝试",
        "system_modify": "系统修改",
        "destructive": "破坏性操作",
        "code_execution": "代码执行",
        "dynamic_loading": "动态加载",
        "accessibility_abuse": "无障碍滥用",
        "device_admin": "设备管理器",
        "notification_abuse": "通知滥用",
        "privacy": "隐私获取",
        "sms_abuse": "短信滥用",
        "peripheral_abuse": "外设滥用",
        "network": "网络通信",
        "encryption": "加密操作",
        "encoding": "编码操作",
    }
    return labels.get(behavior, behavior)


def _analyze_apk_ir(apk_ir: APKIR) -> List[DetectionFinding]:
    """增强的 APK 分析（替换原有函数）"""
    findings: List[DetectionFinding] = []

    # 获取带上下文的字符串
    strings_with_context = getattr(apk_ir, '_strings_with_context', [])
    if not strings_with_context:
        strings_with_context = [{"text": t, "type": _classify_string_type(t), "context": t[:200], "source": "dex"}
                               for t in apk_ir.extracted_strings[:100]]

    static_content_summary = _build_static_content_summary(apk_ir)

    if apk_ir.key_files:
        findings.append(_finding(
            "APK_KEY_FILES_REVIEWED",
            "关键文件证据已提取",
            "low",
            "已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。",
            _join_preview(apk_ir.key_files, limit=12),
            "结合 manifest、资源、签名与代码文件继续确认风险链条。",
        ))

    if static_content_summary["parsed_content_count"]:
        findings.append(_finding(
            "APK_STATIC_CONTENT_PARSED",
            "静态内容解析已完成",
            "low",
            "已从 DEX 字符串、资源文本与配置文件中提取静态内容线索，用于后续规则匹配与证据汇总。",
            static_content_summary["content_preview"],
            "结合命中规则与文件类型继续核验样本行为。",
        ))

    if static_content_summary["matched_rules"]:
        findings.append(_finding(
            "APK_STATIC_RULE_MATCH",
            "静态内容规则命中",
            static_content_summary["severity"],
            "静态内容解析结果命中了敏感 API、远程通信或高风险关键词规则。",
            static_content_summary["match_preview"],
            "优先复核命中的代码路径、字符串上下文与相关组件。",
        ))
    elif static_content_summary["parsed_content_count"]:
        findings.append(_finding(
            "APK_STATIC_RULE_SCAN",
            "静态内容规则扫描完成",
            "low",
            "已完成静态内容规则扫描，但当前样本未命中高风险字符串或敏感 API 模式。",
            static_content_summary["scan_preview"],
            "结合签名、权限和组件信息继续判断样本可信度。",
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

    # 权限检查
    permission_hits = [perm for perm in apk_ir.permissions if any(keyword in perm for keyword in SUSPICIOUS_PERMISSION_KEYWORDS)]
    if permission_hits:
        critical_perms = []
        high_perms = []
        for perm in permission_hits:
            perm_name = perm.split('.')[-1] if '.' in perm else perm
            if perm_name in PERMISSION_RISK_LEVEL:
                level = PERMISSION_RISK_LEVEL[perm_name]
                if level == "critical":
                    critical_perms.append(perm_name)
                elif level == "high":
                    high_perms.append(perm_name)

        severity = "critical" if critical_perms else "high"
        evidence_parts = []
        if critical_perms:
            evidence_parts.append(f"关键权限: {', '.join(critical_perms[:5])}")
        if high_perms:
            evidence_parts.append(f"高危权限: {', '.join(high_perms[:5])}")

        findings.append(_finding(
            "APK_SUSPICIOUS_PERMISSION",
            f"存在 {severity} 敏感权限请求",
            severity,
            f"安装包请求了 {len(permission_hits)} 个敏感权限。",
            "; ".join(evidence_parts),
            "确认权限是否与业务功能一致，避免授予不必要权限。",
        ))

    # ★ 新增：增强的规则匹配
    enhanced_findings = _match_enhanced_rules(apk_ir, strings_with_context)
    findings.extend(enhanced_findings)

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


def _match_enhanced_rules(apk_ir: APKIR, strings_with_context: List[Dict[str, Any]]) -> List[DetectionFinding]:
    """增强的规则匹配"""
    findings: List[DetectionFinding] = []

    # 1. 匹配危险 API
    findings.extend(_match_dangerous_apis(strings_with_context))

    # 2. 匹配恶意行为
    findings.extend(_match_malicious_behaviors(strings_with_context))

    # 3. 检查包名
    findings.extend(_check_package_name(apk_ir))

    # 4. 检查文件路径
    findings.extend(_check_file_paths(apk_ir))

    # 5. 检查权限组合
    findings.extend(_check_permission_combinations(apk_ir))

    # 6. 检查可疑字符串模式
    findings.extend(_match_string_patterns(strings_with_context))

    return findings


def _build_apk_summary(apk_ir: APKIR, findings: List[DetectionFinding]) -> Dict[str, Any]:
    graph_data = apk_ir.graph_data or {}
    graph_stats = graph_data.get("stats", {}) if isinstance(graph_data, dict) else {}
    api_graph = graph_data.get("api_graph", {}) if isinstance(graph_data, dict) else {}
    static_content_summary = _build_static_content_summary(apk_ir)
    return {
        "file_name": apk_ir.file_name,
        "package_name": apk_ir.package_name,
        "bundle_apk_paths": apk_ir.bundle_apk_paths,
        "bundle_apk_count": len(apk_ir.bundle_apk_paths) if apk_ir.bundle_apk_paths else 1,
        "version_name": apk_ir.version_name,
        "version_code": apk_ir.version_code,
        "sha256": apk_ir.sha256,
        "size_bytes": apk_ir.size_bytes,
        "permission_count": len(apk_ir.permissions),
        "component_count": sum(len(bucket) for bucket in (apk_ir.activities, apk_ir.services, apk_ir.receivers, apk_ir.providers)),
        "finding_count": len(findings),
        "key_file_count": len(apk_ir.key_files),
        "evidence_summary": apk_ir.evidence_summary,
        "static_content_summary": static_content_summary,
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


def _build_static_content_summary(apk_ir: APKIR) -> Dict[str, Any]:
    """增强的静态内容摘要"""
    extracted_texts = [text.strip() for text in apk_ir.extracted_strings if str(text).strip()]

    strings_with_context = getattr(apk_ir, '_strings_with_context', [])

    # 统计各类字符串
    string_type_counts = Counter()
    urls = []
    domains = []
    ip_addresses = []
    sensitive_data = []

    for item in strings_with_context:
        string_type = item.get("type", "unknown")
        string_type_counts[string_type] += 1
        text = item.get("text", "")

        if string_type == "url":
            urls.append(text)
        elif string_type == "domain":
            domains.append(text)
        elif string_type == "ip_address":
            ip_addresses.append(text)
        elif string_type == "sensitive_data":
            sensitive_data.append(text)

    # 规则匹配统计
    api_hits = []
    behavior_hits = []
    permission_hits = []
    matched_rules = []

    for text in extracted_texts[:200]:
        api_matches = match_dangerous_api(text)
        for category, api, severity in api_matches:
            api_hits.append({"category": category, "api": api, "severity": severity})
            matched_rules.append({
                "rule_id": f"APK_DANGEROUS_API_{category.upper()}",
                "title": f"敏感 API 规则命中：{category}",
                "evidence": api,
            })

        behavior_matches = match_malicious_behavior(text)
        for behavior, keyword, severity in behavior_matches:
            behavior_hits.append({"behavior": behavior, "keyword": keyword, "severity": severity})
            matched_rules.append({
                "rule_id": f"APK_MALICIOUS_BEHAVIOR_{behavior.upper()}",
                "title": f"恶意行为规则命中：{behavior}",
                "evidence": keyword,
            })

    for perm in apk_ir.permissions:
        perm_name = perm.split('.')[-1] if '.' in perm else perm
        if perm_name in PERMISSION_RISK_LEVEL:
            permission_hits.append({"permission": perm_name, "level": PERMISSION_RISK_LEVEL[perm_name]})
            matched_rules.append({
                "rule_id": "APK_PERMISSION_RISK_MATCH",
                "title": "敏感权限规则命中",
                "evidence": perm_name,
            })

    preview_items = [text[:120] for text in extracted_texts[:10]]
    content_preview = "; ".join(preview_items) or apk_ir.file_name

    match_preview_parts = []
    if api_hits:
        unique_apis = list(set([h["api"] for h in api_hits[:5]]))
        match_preview_parts.append(f"API 调用: {', '.join(unique_apis)}")
    if behavior_hits:
        unique_behaviors = list(set([h["behavior"] for h in behavior_hits[:3]]))
        match_preview_parts.append(f"行为模式: {', '.join(unique_behaviors)}")
    if permission_hits:
        critical_perms = [p["permission"] for p in permission_hits if p["level"] == "critical"]
        if critical_perms:
            match_preview_parts.append(f"关键权限: {', '.join(critical_perms[:5])}")

    severity = "low"
    if any(h["severity"] == "critical" for h in api_hits + behavior_hits):
        severity = "critical"
    elif any(h["severity"] == "high" for h in api_hits + behavior_hits):
        severity = "high"
    elif any(h["severity"] == "medium" for h in api_hits + behavior_hits):
        severity = "medium"
    if any(p["level"] == "critical" for p in permission_hits):
        severity = "critical"
    elif any(p["level"] == "high" for p in permission_hits) and severity != "critical":
        severity = "high"

    return {
        "parsed_content_count": len(extracted_texts),
        "content_preview": content_preview,
        "scan_preview": "; ".join(preview_items[:3]) or apk_ir.file_name,
        "matched_rules": matched_rules,
        "match_preview": "；".join(match_preview_parts) or "未命中明显规则",
        "severity": severity,
        "string_type_counts": dict(string_type_counts),
        "urls_found": urls[:10],
        "domains_found": domains[:10],
        "ip_addresses_found": ip_addresses[:10],
        "sensitive_data_found": sensitive_data[:10],
        "api_hits": api_hits[:20],
        "behavior_hits": behavior_hits[:20],
        "permission_hits": permission_hits,
    }


def _attach_graph_data(apk_ir: APKIR, apk: Any) -> None:
    warnings: List[str] = []
    try:
        extractor = APKGraphExtractor()
        apk_summary = {
            "file_name": apk_ir.file_name,
            "package_name": apk_ir.package_name,
            "version_name": apk_ir.version_name,
            "version_code": apk_ir.version_code,
            "sha256": apk_ir.sha256,
            "size_bytes": apk_ir.size_bytes,
            "permissions": apk_ir.permissions,
            "activities": apk_ir.activities,
            "services": apk_ir.services,
            "receivers": apk_ir.receivers,
            "providers": apk_ir.providers,
            "certificate_subject": apk_ir.certificate_subject,
            "certificate_issuer": apk_ir.certificate_issuer,
            "certificate_sha256": apk_ir.certificate_sha256,
            "extracted_strings": apk_ir.extracted_strings,
            "key_files": apk_ir.key_files,
            "evidence_summary": apk_ir.evidence_summary,
        }
        graph_result = extractor.extract_all(apk, apk_summary)
        apk_ir.graph_data = graph_result
    except Exception as exc:
        warnings.append(f"图结构提取失败：{exc}")
        _attach_graph_fallback(apk_ir, f"图结构提取异常: {exc}", warnings=[f"解析异常: {exc}"])


def _attach_graph_fallback(apk_ir: APKIR, fallback_reason: str, warnings: List[str] | None = None) -> None:
    apk_ir.graph_data = GraphStructure(
        fallback=True,
        fallback_reason=fallback_reason,
        warnings=list(warnings or []),
        cfg={"nodes": [], "edges": []},
        fcg={"nodes": [], "edges": []},
        api_graph={"nodes": [], "edges": [], "api_call_counts": {}},
    )


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
    """增强的证据摘要"""
    summary: Dict[str, Any] = {
        "manifest_files": [],
        "signature_files": [],
        "dex_files": [],
        "resource_files": [],
        "native_libraries": [],
        "config_files": [],
        "text_previews": [],
        "file_type_counts": Counter(),
    }

    for name in names:
        lower = name.lower()
        upper = name.upper()

        if name in MANIFEST_CANDIDATES:
            summary["manifest_files"].append({"name": name})
            summary["file_type_counts"]["manifest"] += 1
            continue
        if upper.startswith(SIGNATURE_PREFIX) and upper.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
            summary["signature_files"].append({"name": name})
            summary["file_type_counts"]["signature"] += 1
            continue
        if lower.endswith(".dex"):
            summary["dex_files"].append({"name": name})
            summary["file_type_counts"]["dex"] += 1
            continue
        if lower.endswith((".so", ".jar", ".aar")):
            summary["native_libraries"].append({"name": name})
            summary["file_type_counts"]["native"] += 1
            continue
        if lower.startswith(("assets/", "res/", "smali/")) and lower.endswith(KEY_FILE_EXTENSIONS):
            summary["resource_files"].append({"name": name})
            summary["file_type_counts"]["resource"] += 1
            continue
        if lower.endswith((".xml", ".json", ".txt", ".ini", ".cfg", ".conf", ".properties", ".js", ".html", ".htm")) and (lower.startswith("assets/") or lower.startswith("res/")):
            summary["config_files"].append({"name": name})
            summary["file_type_counts"]["config"] += 1

    if archive is not None:
        for preview_name in names:
            lower = preview_name.lower()
            if not lower.endswith((".xml", ".json", ".txt", ".ini", ".cfg", ".conf", ".properties", ".js", ".html", ".htm")):
                continue
            try:
                with archive.open(preview_name) as fp:
                    content = fp.read().decode("utf-8", errors="ignore")
                snippet = content[:200].strip()
                if snippet:
                    summary["text_previews"].append({"name": preview_name, "preview": snippet})
                if len(summary["text_previews"]) >= 10:
                    break
            except Exception:
                continue

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