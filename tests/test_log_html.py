"""HTML error page analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_html_500_error_page():
    """HTML 500 server error."""
    log = '<html><head><title>500 Internal Server Error</title></head><body><h1>500 Error</h1></body></html>'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_html_exception_traceback():
    """Python exception in HTML."""
    log = '''<pre>
Traceback (most recent call last):
  File "/app/views.py", line 45, in process
    result = db.query(sql)
AttributeError: 'NoneType' object has no attribute 'query'
</pre>'''
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_html_502_bad_gateway():
    """502 Bad Gateway HTML."""
    log = '<html><title>502 Bad Gateway</title><body><h1>502</h1><p>Service unavailable</p></body></html>'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_html_503_maintenance():
    """503 Service Unavailable (maintenance)."""
    log = '<html><title>503 Service Unavailable</title><body>Under maintenance</body></html>'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_html_nodejs_stack_trace():
    """Node.js error in HTML format."""
    log = '''<pre>
Error: Connection refused
    at TCPConnectWrap.afterConnect [as oncomplete] (/app/server.js:123:15)
    at Protocol._enqueue (/app/db.js:456:23)
</pre>'''
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


if __name__ == "__main__":
    test_html_500_error_page()
    test_html_exception_traceback()
    test_html_502_bad_gateway()
    test_html_503_maintenance()
    test_html_nodejs_stack_trace()
    print("✓ HTML LOG TESTS OK")
