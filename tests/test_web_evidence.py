from alen_audit.web_evidence import analyze_har

def test_web_evidence():
    har = {"log":{"entries":[{"request":{"method":"GET","url":"u"},"response":{"headers":[{"name":"Content-Type","value":"text/html"}],"content":{"text":"__XSS_TEST__"}}}]}}
    out = analyze_har(har)
    assert out["summary"]["total_entries"] == 1
    assert len(out["issues"]) >= 1
