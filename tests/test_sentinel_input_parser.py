from SentinelGuard.parsers.input_parser import parse_target


def test_parse_url_adds_default_https():
    target = parse_target("example.com/login?redirect=http://evil.test")

    assert target.target_type == "url"
    assert target.status == "ready"
    assert target.url.normalized_url == "https://example.com/login?redirect=http://evil.test"
    assert target.url.hostname == "example.com"
    assert "redirect" in target.url.query_params


def test_parse_http_url_keeps_scheme():
    target = parse_target("http://127.0.0.1/login")

    assert target.url.scheme == "http"
    assert target.url.is_ip_address is True


def test_small_program_placeholder():
    target = parse_target("demo.wxapkg")

    assert target.target_type == "small_program"
    assert target.status == "not_implemented"


def test_app_placeholder():
    target = parse_target("sample.apk")

    assert target.target_type == "app"
    assert target.status == "not_implemented"


def test_invalid_input():
    target = parse_target("")

    assert target.target_type == "unknown"
    assert target.status == "invalid"
