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


def test_parse_apk_path():
    target = parse_target("sample.apk")

    assert target.target_type == "apk"
    assert target.status == "ready"
    assert target.apk.file_name == "sample.apk"


def test_parse_explicit_apk_type():
    target = parse_target("C:/samples/demo.apk", target_type="apk")

    assert target.target_type == "apk"
    assert target.status == "ready"


def test_url_with_apk_suffix_still_parses_as_url():
    target = parse_target("https://example.com/files/tool.apk")

    assert target.target_type == "url"
    assert target.url.path.endswith("tool.apk")


def test_invalid_input():
    target = parse_target("")

    assert target.target_type == "unknown"
    assert target.status == "invalid"
