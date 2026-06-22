from __future__ import annotations

from typing import Dict, Iterable, Tuple


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
