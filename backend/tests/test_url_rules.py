import pytest

from app.analyzers.url_rules import url_rules
from app.core.scoring import combine, noisy_or, verdict_for
from app.core.urltools import InvalidURL, parse_ip, parse_url, typosquat_target
from app.ml.features import FEATURE_NAMES, extract_features


def ids(url: str) -> set[str]:
    return {f.id for f in url_rules(parse_url(url))}


def test_parse_normalizes_scheme_and_registered_domain():
    u = parse_url("Login.PayPal.co.uk/path?x=1")
    assert u.scheme == "http"
    assert u.host == "login.paypal.co.uk"
    assert u.registered_domain == "paypal.co.uk"
    assert u.subdomain == "login"


@pytest.mark.parametrize("bad", ["", "ftp://example.com", "javascript:alert(1)", "http://"])
def test_parse_rejects_invalid(bad):
    with pytest.raises(InvalidURL):
        parse_url(bad)


@pytest.mark.parametrize("host,expected", [
    ("192.168.0.1", "192.168.0.1"),
    ("3232235521", "192.168.0.1"),
    ("0xC0A80001", "192.168.0.1"),
    ("0300.0250.0.1", "192.168.0.1"),
    ("example.com", None),
])
def test_obfuscated_ip_detection(host, expected):
    ip = parse_ip(host)
    assert (str(ip) if ip else None) == expected


@pytest.mark.parametrize("label,brand", [
    ("paypa1", "paypal"), ("micros0ft-support", "microsoft"), ("arnazon", "amazon"), ("netfllx", "netflix"),
])
def test_typosquats_detected(label, brand):
    assert typosquat_target(label)[0] == brand


@pytest.mark.parametrize("label", ["paypal", "cooking", "live-stream", "apply-now", "github"])
def test_typosquat_false_positives_avoided(label):
    assert typosquat_target(label) is None


def test_brand_in_subdomain_and_risky_tld():
    found = ids("http://paypal.com.secure-login.xyz/webscr/verify.php")
    assert {"url.brand_subdomain", "url.tld_high", "url.keywords", "url.no_https"} <= found


def test_userinfo_trick():
    assert "url.userinfo" in ids("https://www.google.com@evil-site.top/login")


def test_ip_host_and_port():
    assert {"url.ip_host", "url.port"} <= ids("http://45.12.8.9:8080/apple/id.php")


def test_free_hosting_and_combosquat():
    found = ids("https://chase-secure-alert.web.app/")
    assert "url.free_hosting" in found


def test_popular_domain_is_trusted():
    findings = url_rules(parse_url("https://accounts.google.com/signin"))
    assert any(f.kind == "trust" and f.id == "url.popular_domain" for f in findings)
    assert not any(f.id.startswith("url.brand") for f in findings)


def test_embedded_redirect():
    assert "url.embedded_redirect" in ids("https://example.com/out?url=https://evil.example.net/login")


def test_features_complete_and_numeric():
    feats = extract_features("https://paypal-secure.xyz/login")
    assert list(feats) == FEATURE_NAMES
    assert all(isinstance(v, float) for v in feats.values())
    assert feats["brand_combosquat"] == 1.0
    assert feats["tld_high_risk"] == 1.0


def test_scoring_model():
    assert noisy_or([]) == 0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert verdict_for(10) == "safe" and verdict_for(50) == "suspicious" and verdict_for(80) == "malicious"
    from app.schemas import Finding

    trust = Finding(id="t", category="x", kind="trust", title="t", weight=0.5)
    risk = Finding(id="r", category="x", title="r", weight=0.6)
    out = combine([risk, trust], ml_probability=None)
    assert out["risk_score"] == 48  # 0.6 * (1 - 0.5 * (1 - 0.6))
    assert combine([], ml_probability=0.0, intel_malicious=1)["risk_score"] == 90
