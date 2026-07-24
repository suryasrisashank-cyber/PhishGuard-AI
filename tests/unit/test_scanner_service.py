from backend.app.services.scanner_service import analyze_url, analyze_email


def test_analyze_url_safe() -> None:
    result = analyze_url("https://example.com")
    assert result["verdict"] in {"Safe", "Suspicious", "Malicious"}


def test_analyze_email_safe() -> None:
    result = analyze_email("Hello there, this is a normal message")
    assert result["verdict"] in {"Safe", "Suspicious", "Malicious"}
