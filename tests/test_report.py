from alen_audit.reporting import render_report

def test_render(tmp_path):
    payload = {
        "target":"t",
        "generated_at":"2026-02-11T00:00:00Z",
        "findings":[{"id":"1","title":"xss evidence __XSS_TEST__","severity":"low","location":"/","tags":["xss"],"cwe":"CWE-79"}]
    }
    out = tmp_path / "out"
    render_report(payload, str(out), "P", "O")
    assert (out / "report.html").exists()
    assert (out / "summary.json").exists()
    assert (out / "threat_model.md").exists()
