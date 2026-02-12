from alen_audit.mapping import owasp_for_cwe, normalize_severity

def test_owasp_mapping():
    assert any("Injection" in x for x in owasp_for_cwe("CWE-89"))

def test_normalize():
    assert normalize_severity("H") == "high"
