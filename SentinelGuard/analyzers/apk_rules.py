from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple


SUSPICIOUS_PERMISSION_KEYWORDS: Tuple[str, ...] = (
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

SUSPICIOUS_STRING_KEYWORDS: Tuple[str, ...] = (
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

SUSPICIOUS_COMPONENT_KEYWORDS: Tuple[str, ...] = (
    "BootReceiver",
    "AdminReceiver",
    "AccessibilityService",
    "DeviceAdminReceiver",
    "JobService",
)

KEY_FILE_EXTENSIONS: Tuple[str, ...] = (
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

MANIFEST_CANDIDATES: Tuple[str, ...] = (
    "AndroidManifest.xml",
    "manifest/AndroidManifest.xml",
)

SIGNATURE_PREFIX = "META-INF/"

SENSITIVE_API_RULES: Dict[str, Tuple[str, ...]] = {
    "privacy": (
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/telephony/TelephonyManager;->getImei",
        "Landroid/telephony/TelephonyManager;->getSubscriberId",
        "Landroid/provider/Settings$Secure;->getString",
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Landroid/accounts/AccountManager;->getAccounts",
    ),
    "payment": (
        "Landroid/app/PendingIntent;->getActivity",
        "Landroid/content/Intent;->setPackage",
        "Landroid/net/Uri;->parse",
        "Ljavax/crypto/Cipher;->doFinal",
    ),
    "system": (
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/System;->loadLibrary",
        "Ljava/lang/ClassLoader;->loadClass",
        "Ldalvik/system/DexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>",
    ),
    "network": (
        "Ljava/net/URL;->openConnection",
        "Ljava/net/HttpURLConnection;->connect",
        "Lokhttp3/OkHttpClient;->newCall",
        "Lorg/apache/http/client/HttpClient;->execute",
        "Ljava/net/Socket;->connect",
    ),
    "reflection": (
        "Ljava/lang/reflect/Method;->invoke",
        "Ljava/lang/Class;->forName",
        "Ljava/lang/reflect/Field;->get",
        "Ljava/lang/reflect/Field;->set",
    ),
}


SENSITIVE_API_WEIGHTS: Dict[str, int] = {
    "privacy": 4,
    "system": 4,
    "network": 3,
    "payment": 3,
    "reflection": 2,
}


def iter_sensitive_api_signatures() -> Iterable[str]:
    for signatures in SENSITIVE_API_RULES.values():
        yield from signatures


def match_sensitive_api(text: str) -> tuple[str, str]:
    lowered = (text or "").lower()
    for category, signatures in SENSITIVE_API_RULES.items():
        for signature in signatures:
            if signature.lower() in lowered:
                return signature, category
    return "", "unknown"


def sensitive_api_category(signature: str) -> str:
    for category, signatures in SENSITIVE_API_RULES.items():
        if signature in signatures:
            return category
    return "unknown"


def sensitive_api_weight(signature: str) -> int:
    category = sensitive_api_category(signature)
    return SENSITIVE_API_WEIGHTS.get(category, 2)


# ============ 新增：危险 API 调用规则（细粒度分类） ============
DANGEROUS_API_RULES: Dict[str, Tuple[str, ...]] = {
    "privacy_leak": (
        "getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber",
        "getLine1Number", "getVoiceMailNumber", "getDeviceSoftwareVersion",
        "getCellLocation", "getAllCellInfo", "getNeighboringCellInfo",
        "getLastKnownLocation", "requestLocationUpdates", "getAccounts",
        "getAccountsByType", "getAuthenticatorTypes", "getContentResolver",
        "openFileOutput", "openFileInput",
    ),
    "file_operation": (
        "FileOutputStream", "FileWriter", "RandomAccessFile", "createNewFile",
        "delete", "renameTo", "mkdir", "mkdirs", "listFiles", "listRoots",
        "getAbsolutePath", "getCanonicalPath",
    ),
    "network": (
        "URL", "HttpURLConnection", "HttpsURLConnection", "OkHttpClient",
        "Retrofit", "Volley", "Socket", "ServerSocket", "DatagramSocket",
        "MulticastSocket", "URLConnection", "openConnection", "connect",
        "getInputStream", "getOutputStream", "write", "read",
    ),
    "code_execution": (
        "Runtime.exec", "ProcessBuilder", "start", "loadLibrary",
        "System.load", "DexClassLoader", "PathClassLoader",
        "InMemoryDexClassLoader", "classForName", "forName",
    ),
    "reflection": (
        "getDeclaredMethod", "getDeclaredField", "getMethod", "getField",
        "setAccessible", "Method.invoke", "Field.get", "Field.set",
        "setInt", "setLong", "setObject",
    ),
    "crypto": (
        "Cipher", "getInstance", "doFinal", "init", "KeyGenerator",
        "SecretKeySpec", "Mac", "Signature", "MessageDigest",
        "Base64", "encodeToString", "decode",
    ),
    "system_command": (
        "sh", "bash", "su", "mount", "chmod", "chown", "rm", "cp", "mv",
        "kill", "ps", "top", "netstat", "ifconfig", "iptables",
    ),
    "dynamic_loading": (
        "DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader",
        "loadApk", "loadPackage", "loadDex",
    ),
    "persistence": (
        "BOOT_COMPLETED", "RECEIVE_BOOT_COMPLETED", "DeviceAdminReceiver",
        "AccessibilityService", "NotificationListenerService",
        "VoiceInteractionService", "TileService",
    ),
    "payment": (
        "Alipay", "WeChat", "PayPal", "UnionPay", "IAP",
        "inapppurchase", "billing", "purchase",
    ),
}


# ============ 新增：可疑包名模式 ============
SUSPICIOUS_PACKAGE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"^com\.([a-z]+)\.([a-z]+)\2", "重复的包名段，疑似自动生成"),
    (r"^com\.([a-z]{1,3})\.([a-z]{1,3})\.([a-z]{1,3})$", "包名段过短，疑似随机生成"),
    (r"(google|facebook|twitter|instagram|whatsapp|paypal|alipay|wechat|qq|taobao|jd|baidu)\d+", "包含知名品牌名+数字，疑似仿冒"),
    (r"^[a-z]{8,15}\.[a-z]{3,8}$", "包名结构异常简单，疑似自动生成"),
    (r"systemui|android\.system", "伪装系统应用"),
    (r"\.(update|installer|downloader|loader|crypt|encrypt)\.", "包含可疑关键词"),
)


# ============ 新增：可疑文件路径模式 ============
SUSPICIOUS_FILE_PATH_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"assets/.*\.(js|html|htm|txt|json|xml)", "可执行或配置文件存放在 assets 目录"),
    (r"lib/.*\.so", "Native 库文件"),
    (r"res/raw/.*\.(mp3|wav|mp4|3gp)", "媒体文件，可能用于隐蔽通信"),
    (r"META-INF/.*\.(RSA|DSA|EC)", "证书文件"),
    (r"classes\d*\.dex", "DEX 代码文件"),
    (r"\.(jpg|jpeg|png|gif|bmp)\.(dex|jar|apk|so)", "图片文件伪装成可执行文件"),
)


# ============ 新增：恶意行为关键词 ============
MALICIOUS_BEHAVIOR_KEYWORDS: Tuple[Tuple[str, str, str], ...] = (
    ("root", "root_attempt", "high"),
    ("su", "root_attempt", "high"),
    ("chmod", "system_modify", "high"),
    ("mount -o", "system_modify", "high"),
    ("rm -rf", "destructive", "critical"),
    ("Runtime.exec", "code_execution", "high"),
    ("ProcessBuilder", "code_execution", "high"),
    ("DexClassLoader", "dynamic_loading", "high"),
    ("AccessibilityService", "accessibility_abuse", "high"),
    ("DeviceAdminReceiver", "device_admin", "high"),
    ("NotificationListener", "notification_abuse", "medium"),
    ("getDeviceId", "privacy", "high"),
    ("getSubscriberId", "privacy", "high"),
    ("getLastKnownLocation", "privacy", "high"),
    ("getAccounts", "privacy", "high"),
    ("SmsManager", "sms_abuse", "high"),
    ("sendTextMessage", "sms_abuse", "high"),
    ("TelephonyManager", "privacy", "medium"),
    ("Camera", "peripheral_abuse", "high"),
    ("MediaRecorder", "peripheral_abuse", "high"),
    ("AudioRecord", "peripheral_abuse", "high"),
    ("HttpURLConnection", "network", "medium"),
    ("Cipher", "encryption", "medium"),
    ("SecretKeySpec", "encryption", "medium"),
    ("Base64", "encoding", "low"),
    ("encrypt", "encryption", "medium"),
    ("decrypt", "encryption", "medium"),
    ("eval", "code_execution", "critical"),
    ("addJavascriptInterface", "code_execution", "high"),
    ("loadUrl", "network", "medium"),
    ("postUrl", "network", "medium"),
)


# ============ 新增：权限风险等级映射 ============
PERMISSION_RISK_LEVEL: Dict[str, str] = {
    "READ_SMS": "critical",
    "SEND_SMS": "critical",
    "RECEIVE_SMS": "critical",
    "READ_CONTACTS": "high",
    "WRITE_CONTACTS": "high",
    "READ_CALL_LOG": "high",
    "WRITE_CALL_LOG": "high",
    "RECORD_AUDIO": "high",
    "CAMERA": "high",
    "ACCESS_FINE_LOCATION": "high",
    "ACCESS_COARSE_LOCATION": "medium",
    "REQUEST_INSTALL_PACKAGES": "critical",
    "SYSTEM_ALERT_WINDOW": "high",
    "BIND_ACCESSIBILITY_SERVICE": "critical",
    "QUERY_ALL_PACKAGES": "high",
    "MANAGE_EXTERNAL_STORAGE": "critical",
    "WRITE_EXTERNAL_STORAGE": "medium",
    "READ_EXTERNAL_STORAGE": "low",
    "INSTALL_PACKAGES": "critical",
    "DELETE_PACKAGES": "critical",
    "READ_PHONE_STATE": "high",
    "PROCESS_OUTGOING_CALLS": "high",
    "GET_ACCOUNTS": "high",
}


# ============ 新增：工具函数 ============

def match_dangerous_api(text: str) -> List[Tuple[str, str, str]]:
    """匹配危险 API，返回 (category, api_name, severity)"""
    results: List[Tuple[str, str, str]] = []
    lowered = text.lower()

    for category, apis in DANGEROUS_API_RULES.items():
        for api in apis:
            if api.lower() in lowered:
                severity = {
                    "privacy_leak": "high",
                    "file_operation": "medium",
                    "network": "medium",
                    "code_execution": "critical",
                    "reflection": "high",
                    "crypto": "medium",
                    "system_command": "critical",
                    "dynamic_loading": "high",
                    "persistence": "high",
                    "payment": "medium",
                }.get(category, "medium")
                results.append((category, api, severity))

    return results


def match_malicious_behavior(text: str) -> List[Tuple[str, str, str]]:
    """匹配恶意行为关键词，返回 (behavior, keyword, severity)"""
    results: List[Tuple[str, str, str]] = []
    lowered = text.lower()

    for keyword, behavior, severity in MALICIOUS_BEHAVIOR_KEYWORDS:
        if keyword.lower() in lowered:
            results.append((behavior, keyword, severity))

    return results


def check_suspicious_package(package_name: str) -> List[Tuple[str, str]]:
    """检查包名是否可疑，返回 (pattern, reason)"""
    results: List[Tuple[str, str]] = []

    if not package_name:
        return results

    for pattern, reason in SUSPICIOUS_PACKAGE_PATTERNS:
        if re.search(pattern, package_name, re.IGNORECASE):
            results.append((pattern, reason))

    return results


def check_suspicious_file_paths(file_names: List[str]) -> List[Tuple[str, str, str]]:
    """检查文件路径是否可疑，返回 (file_name, pattern, reason)"""
    results: List[Tuple[str, str, str]] = []

    for file_name in file_names:
        for pattern, reason in SUSPICIOUS_FILE_PATH_PATTERNS:
            if re.search(pattern, file_name, re.IGNORECASE):
                results.append((file_name, pattern, reason))
                break

    return results
