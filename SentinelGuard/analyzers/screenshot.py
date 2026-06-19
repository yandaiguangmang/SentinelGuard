from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _load_sync_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    return sync_playwright


def _normalize_proxy_settings(proxy: Any) -> Optional[Dict[str, str]]:
    if not proxy:
        return None

    if isinstance(proxy, str):
        server = proxy.strip()
        return {"server": server} if server else None

    if isinstance(proxy, dict):
        server = (proxy.get("server") or proxy.get("https") or proxy.get("http") or proxy.get("all") or "").strip()
        if not server:
            return None

        proxy_settings: Dict[str, str] = {"server": server}
        username = (proxy.get("username") or proxy.get("user") or "").strip()
        password = (proxy.get("password") or "").strip()
        if username:
            proxy_settings["username"] = username
        if password:
            proxy_settings["password"] = password
        return proxy_settings

    return None


def capture_page_screenshot(
    url: str,
    proxy: Any = None,
    timeout_seconds: int = 15,
    viewport: Optional[Dict[str, int]] = None,
    extra_wait_ms: int = 1200,
) -> Optional[Dict[str, Any]]:
    sync_playwright = _load_sync_playwright()
    if sync_playwright is None:
        return None

    page = None
    context = None
    browser = None
    try:
        viewport = viewport or {"width": 1440, "height": 1600}
        proxy_settings = _normalize_proxy_settings(proxy)
        timeout_ms = max(1, int(timeout_seconds)) * 1000

        with sync_playwright() as playwright:
            launch_kwargs: Dict[str, Any] = {"headless": True}
            if proxy_settings:
                launch_kwargs["proxy"] = proxy_settings
            browser = playwright.chromium.launch(**launch_kwargs)
            context = browser.new_context(ignore_https_errors=True, viewport=viewport)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                pass
            if extra_wait_ms > 0:
                page.wait_for_timeout(extra_wait_ms)
            screenshot_bytes = page.screenshot(full_page=True, type="png")
            return {
                "url": url,
                "final_url": page.url,
                "mime_type": "image/png",
                "size_bytes": len(screenshot_bytes),
                "base64": base64.b64encode(screenshot_bytes).decode("ascii"),
                "viewport": viewport,
                "width": viewport.get("width"),
                "height": viewport.get("height"),
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "page_title": page.title() if page else "",
                "proxy_used": bool(proxy_settings),
            }
    except Exception:
        return None
    finally:
        try:
            if page is not None:
                page.close()
        except Exception:
            pass
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
