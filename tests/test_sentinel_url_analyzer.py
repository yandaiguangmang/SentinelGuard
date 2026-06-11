from SentinelGuard.analyzers import url_analyzer
from SentinelGuard.judgement import run_detection
from SentinelGuard.parsers.input_parser import parse_target


class FakeRaw:
    def __init__(self, body):
        self.body = body

    def read(self, *_args, **_kwargs):
        return self.body


class FakeResponse:
    def __init__(self):
        self.url = "https://safe.example/login"
        self.history = [type("History", (), {"url": "http://example.com/start"})()]
        self.headers = {"content-type": "text/html; charset=utf-8"}
        self.status_code = 200
        self.encoding = "utf-8"
        self.raw = FakeRaw(b"<html><head><title>Login</title></head><body><form action='/login'><input type='password'><input type='hidden'><a href='tool.apk'>download</a></form></body></html>")


class FakeRequests:
    class RequestException(Exception):
        pass

    @staticmethod
    def get(*_args, **_kwargs):
        return FakeResponse()


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

    assert "REDIRECT_CROSS_DOMAIN" in rule_ids
    assert "PAGE_PASSWORD_FORM" in rule_ids
    assert "PAGE_DOWNLOAD_LINK" in rule_ids
    assert result["page_summary"]["title"] == "Login"


def test_run_detection_scores_high_for_phishing_signals(monkeypatch):
    monkeypatch.setattr(url_analyzer, "requests", FakeRequests)

    report = run_detection("http://example.com/login?redirect=http://evil.test", fetch_page=True)

    assert report.risk_level in {"high", "critical"}
    assert report.score > 0
    assert report.html_report_path
