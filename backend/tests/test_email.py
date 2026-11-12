import asyncio

from app.analyzers.email_scan import extract_links, parse_message, scan_email


def run(coro):
    return asyncio.run(coro)


def test_phishing_sample_is_malicious(sample):
    result = run(scan_email(sample("phishing_paypal.eml"), deep=False, use_intel=False))
    ids = {f["id"] for f in result["findings"]}
    assert result["verdict"] == "malicious"
    assert {"auth.dmarc_fail", "email.display_name_spoof", "link.text_mismatch",
            "attachment.double_extension", "email.reply_to_mismatch"} <= ids
    auth = result["details"]["authentication"]
    assert (auth["spf"], auth["dkim"], auth["dmarc"]) == ("softfail", "none", "fail")


def test_legit_sample_is_safe(sample):
    result = run(scan_email(sample("legit_github.eml"), deep=False, use_intel=False))
    assert result["verdict"] == "safe"
    assert any(f["id"] == "auth.all_pass" for f in result["findings"])


def test_fields_without_headers():
    result = run(scan_email(None, sender="Netflix <billing@netflix-payments-update.com>",
                            subject="Payment declined",
                            body="Dear customer, update your payment details at https://netflix-payments-update.com/billing",
                            deep=False, use_intel=False))
    ids = {f["id"] for f in result["findings"]}
    assert "email.display_name_spoof" in ids and "auth.no_results" in ids
    assert result["verdict"] != "safe"


def test_anchor_text_is_not_a_link():
    msg = parse_message(None, None, None, '<p><a href="https://evil.example/x">https://bank.com/login</a></p>')
    rich = msg.get_body(("html",)).get_content()
    links = extract_links("", rich)
    urls = [l["url"] for l in links]
    assert urls == ["https://evil.example/x"]
    assert links[0]["mismatch"] == {"shown": "bank.com", "actual": "evil.example"}


def test_unclosed_tags_do_not_blow_up():
    import time

    start = time.perf_counter()
    extract_links("", "<a href=x>" * 50_000 + "<script>" * 50_000)
    assert time.perf_counter() - start < 2
