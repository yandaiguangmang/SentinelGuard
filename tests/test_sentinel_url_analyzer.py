from SentinelGuard.analyzers import url_analyzer
from SentinelGuard.analyzers.url_deep_analyzer import _load_json_payload
from SentinelGuard.judgement import run_detection
from SentinelGuard.parsers.input_parser import parse_target
from SentinelGuard.state import DetectionFinding


class FakeRaw:
    def __init__(self, body):
        self.body = body

    def read(self, *_args, **_kwargs):
        return self.body


class FakeResponse:
    def __init__(self):
        self.url = "http://example.com/start"
        self.history = []
        self.headers = {"content-type": "text/html; charset=utf-8"}
        self.status_code = 200
        self.encoding = "utf-8"
        self.raw = FakeRaw(b"<html><head><title>Login</title></head><body><form action='/login'><input type='password'><input type='hidden'><a href='tool.apk'>download</a></form></body></html>")


class RedirectResponse:
    def __init__(self):
        self.url = "http://example.com/start"
        self.history = []
        self.headers = {
            "content-type": "text/html; charset=utf-8",
            "location": "https://safe.example/login",
        }
        self.status_code = 302
        self.encoding = "utf-8"
        self.raw = FakeRaw(b"")


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.trust_env = False
        self.proxies = {}

    def get(self, *args, **kwargs):
        return FakeResponse()


class FakeRequests:
    class RequestException(Exception):
        pass

    class exceptions:
        class SSLError(Exception):
            pass

    @staticmethod
    def Session():
        return FakeSession()


def test_url_structure_rules_without_fetch():
    target = parse_target("http://127.0.0.1/login?redirect=http://evil.test")
    result = url_analyzer.analyze_url(target, fetch_page=False)
    rule_ids = {finding.rule_id for finding in result["findings"]}

    assert "URL_NON_HTTPS" in rule_ids
    assert "URL_IP_HOST" in rule_ids
    assert "URL_REDIRECT_PARAM" in rule_ids


def test_page_rules_with_monkeypatched_fetch(monkeypatch):
    monkeypatch.setattr(url_analyzer, "requests", FakeRequests)

    target = parse_target("http://example.com/start")
    result = url_analyzer.analyze_url(target, fetch_page=True)
    rule_ids = {finding.rule_id for finding in result["findings"]}

    assert "PAGE_PASSWORD_FORM" in rule_ids
    assert "PAGE_DOWNLOAD_LINK" in rule_ids
    assert "REDIRECT_CROSS_DOMAIN" not in rule_ids
    assert result["page_summary"]["title"] == "Login"


def test_redirect_response_is_not_followed_but_is_recorded(monkeypatch):
    monkeypatch.setattr(url_analyzer, "requests", FakeRequests)

    class RedirectSession(FakeSession):
        def get(self, *args, **kwargs):
            return RedirectResponse()

    monkeypatch.setattr(url_analyzer, "_build_session", lambda use_env_proxy=True: RedirectSession())

    target = parse_target("http://example.com/start")
    result = url_analyzer.analyze_url(target, fetch_page=True)

    rule_ids = {finding.rule_id for finding in result["findings"]}

    assert "REDIRECT_CROSS_DOMAIN" in rule_ids
    assert result["redirect_chain"] == ["http://example.com/start", "https://safe.example/login"]
    assert result["page_summary"]["status_code"] == 302
    assert result["page_summary"]["redirect_location"] == "https://safe.example/login"
    assert result["page_summary"]["redirect_final_url"] == "https://safe.example/login"
    assert result["page_summary"]["final_url"] == "https://safe.example/login"


def test_run_detection_scores_high_for_phishing_signals(monkeypatch):
    monkeypatch.setattr(url_analyzer, "requests", FakeRequests)

    report = run_detection("http://example.com/login?redirect=http://evil.test", fetch_page=True)

    assert report.risk_level in {"high", "critical"}
    assert report.score > 0
    assert report.html_report_path


def test_proxy_failure_falls_back_to_direct(monkeypatch):
    monkeypatch.setattr(url_analyzer, "requests", FakeRequests)
    monkeypatch.setattr(url_analyzer, "_build_fetch_profiles", lambda *args, **kwargs: [
        {"name": "proxy", "proxies": {"http": "http://127.0.0.1:7890"}, "verify": True},
        {"name": "direct", "proxies": {}, "verify": True},
    ])

    created_sessions = []

    class ProxySession(FakeSession):
        def get(self, *args, **kwargs):
            raise FakeRequests.RequestException("proxy failed")

    class DirectSession(FakeSession):
        def get(self, *args, **kwargs):
            return FakeResponse()

    def fake_build_session(use_env_proxy: bool = True):
        created_sessions.append(use_env_proxy)
        return ProxySession() if use_env_proxy else DirectSession()

    monkeypatch.setattr(url_analyzer, "_build_session", fake_build_session)

    target = parse_target("http://example.com/start")
    result = url_analyzer.analyze_url(target, fetch_page=True)

    rule_ids = {finding.rule_id for finding in result["findings"]}
    assert "PAGE_PROXY_FALLBACK_DIRECT" in rule_ids
    assert result["page_summary"]["fetch_mode"] == "direct"
    assert created_sessions == [True, False]


def test_proxy_url_normalization_for_local_proxy():
    from SentinelGuard.state import AnalysisRuntimeConfig

    cfg = AnalysisRuntimeConfig(
        proxy_http="",
        proxy_https="https://10.250.167.176:7890",
        proxy_all="",
    )

    proxies = cfg.proxy_dict()
    assert proxies["https"] == "http://10.250.167.176:7890"
    assert cfg.proxy_warnings()


def test_score_reflects_severity_strength(monkeypatch):
    from SentinelGuard import judgement

    monkeypatch.setattr(judgement, "analyze_url", lambda *_args, **_kwargs: {
        "findings": [
            DetectionFinding(
                rule_id="TEST_LOW",
                title="低危证据",
                severity="low",
                description="",
                evidence="low",
                recommendation="",
            ),
            DetectionFinding(
                rule_id="TEST_HIGH",
                title="高危证据",
                severity="high",
                description="",
                evidence="high",
                recommendation="",
            ),
        ],
        "redirect_chain": [],
        "page_summary": {},
    })

    report = run_detection("http://example.com", fetch_page=False)

    assert report.risk_level == "high"
    assert report.score >= 50


def test_load_json_payload_recovers_object_from_top_level_list():
    payload = '["noise", {"opinion": "recovered", "risk_hint": "high"}]'

    data = _load_json_payload(payload)

    assert data["opinion"] == "recovered"
    assert data["risk_hint"] == "high"
