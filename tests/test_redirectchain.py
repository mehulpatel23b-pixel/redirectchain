"""Tests for redirectchain. Run: python3 -m pytest -q"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redirectchain as rc  # noqa: E402


def codes(findings):
    return {f["code"] for f in findings}


def hop(url, location=None, status=None, body=""):
    return {"n": 0, "url": url, "status": status, "location": location, "body": body}


def run(hops):
    found, _enriched = rc.analyse(hops)
    for i, h in enumerate(hops):
        h["n"] = i
    found, _enriched = rc.analyse(hops)
    return found


def test_registrable_handles_multi_part_suffixes():
    assert rc.registrable("a.b.example.co.uk") == "example.co.uk"
    assert rc.registrable("mail.example.com") == "example.com"
    assert rc.registrable("example.com") == "example.com"


def test_shortener_and_plaintext_and_userinfo_detected():
    found = run([hop("http://user@bit.ly/abc")])
    assert {"RC-SHORTENER", "RC-PLAINTEXT", "RC-USERINFO"} <= codes(found)


def test_open_redirect_detected_when_param_crosses_domain():
    found = run([hop("https://trusted.example/r?next=https://evil.example/login")])
    assert "RC-OPEN-REDIRECT" in codes(found)
    assert any(f["severity"] == "high" for f in found if f["code"] == "RC-OPEN-REDIRECT")


def test_redirect_param_staying_on_site_is_low():
    found = run([hop("https://trusted.example/r?next=/dashboard")])
    assert "RC-OPEN-REDIRECT" not in codes(found)


def test_https_to_http_downgrade_is_high():
    found = run([hop("https://a.example/", location="http://b.example/x", status=302),
                 hop("http://b.example/x")])
    assert "RC-DOWNGRADE" in codes(found)


def test_ip_host_and_punycode():
    found = run([hop("https://192.0.2.10/login"), hop("https://xn--pypal-4ve.example/login")])
    assert "RC-IP-HOST" in codes(found)
    assert "RC-PUNYCODE" in codes(found)


def test_meta_refresh_and_js_redirect_read_from_body():
    body = '<meta http-equiv="refresh" content="0; url=https://evil.example/x">'
    found = run([hop("https://a.example/", status=200, body=body)])
    assert "RC-META-REFRESH" in codes(found)

    js = "<script>window.location.replace('https://evil.example/login')</script>"
    found = run([hop("https://a.example/", status=200, body=js)])
    assert "RC-JS-REDIRECT" in codes(found)


def test_script_scheme_is_critical():
    found = run([hop("javascript:alert(1)")])
    assert "RC-SCRIPT-SCHEME" in codes(found)
    assert found[0]["severity"] == "critical"


def test_cross_domain_transitions_and_long_chain():
    hops = [hop("https://a.example/x", location="https://b.example/x", status=302),
            hop("https://b.example/x", location="https://c.example/x", status=302),
            hop("https://c.example/x", location="https://d.example/x", status=302),
            hop("https://d.example/x", location="https://e.example/x", status=302),
            hop("https://e.example/x", location="https://f.example/x", status=302),
            hop("https://f.example/x", status=200)]
    found = run(hops)
    assert "RC-CROSS-DOMAIN" in codes(found)
    assert "RC-LONG-CHAIN" in codes(found)


def test_loop_note_flagged():
    hops = [{"n": 0, "url": "https://a.example/", "status": None, "location": None, "body": ""},
            {"n": 1, "url": "https://a.example/", "status": None, "location": None,
             "body": "", "note": "loop"}]
    found = run(hops)
    assert "RC-LOOP" in codes(found)


def test_encoded_blob_and_tracking_params():
    blob = "a" * 48
    found = run([hop("https://a.example/%s?utm_source=x&gclid=y" % blob)])
    assert "RC-ENCODED-PATH" in codes(found)
    assert "RC-TRACKING" in codes(found)


def test_load_chain_json_and_text(tmp_path):
    path = tmp_path / "chain.json"
    path.write_text(json.dumps([
        {"url": "https://bit.ly/x", "status": 301, "location": "https://evil.example/"},
        {"url": "https://evil.example/", "status": 200},
    ]), encoding="utf-8")
    hops = rc.load_chain(str(path))
    assert len(hops) == 2
    assert hops[0]["status"] == 301

    text = tmp_path / "chain.txt"
    text.write_text("# a chain\nhttps://a.example/\n302 https://b.example/\n", encoding="utf-8")
    hops = rc.load_chain(str(text))
    assert len(hops) == 2
    assert hops[1]["status"] == 302
    assert hops[1]["url"] == "https://b.example/"


def test_load_chain_errors(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("   \n", encoding="utf-8")
    try:
        rc.load_chain(str(empty))
    except rc.ChainError:
        pass
    else:
        raise AssertionError("expected ChainError")
    assert rc.main(["--chain", str(tmp_path / "missing.txt")]) == 2


def test_scoring_orders_severity():
    risk_clean, grade_clean = rc.score([])
    risk_bad, grade_bad = rc.score([{"severity": "critical"}, {"severity": "high"}])
    assert risk_clean == 0 and grade_clean == "A"
    assert risk_bad > risk_clean
    assert grade_bad in "DEF"


def test_cli_json_and_gate(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"url": "http://user@bit.ly/x?url=https://evil.example/a"}]),
                   encoding="utf-8")
    assert rc.main(["--chain", str(bad), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["gate"] == "FAIL"
    assert payload["findings"]

    clean = tmp_path / "clean.txt"
    clean.write_text("https://example.com/pricing\n", encoding="utf-8")
    assert rc.main(["--chain", str(clean)]) == 0


def test_cli_requires_input():
    assert rc.main([]) == 2
