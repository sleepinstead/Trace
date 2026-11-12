def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["model_loaded"] is True


def test_url_scan_saved_and_listed(client):
    r = client.post("/api/scan/url", json={"url": "http://paypal.com.secure-login.xyz/webscr/verify.php", "deep": False, "use_intel": False})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "malicious"
    assert 0 <= body["risk_score"] <= 100
    assert body["details"]["ml"]["probability"] > 0.5

    detail = client.get(f"/api/scans/{body['id']}")
    assert detail.status_code == 200 and detail.json()["target"] == body["target"]

    listing = client.get("/api/scans", params={"scan_type": "url", "verdict": "malicious"}).json()
    assert any(item["id"] == body["id"] for item in listing["items"])

    stats = client.get("/api/stats").json()
    assert stats["total_scans"] >= 1 and stats["by_verdict"]["malicious"] >= 1

    assert client.delete(f"/api/scans/{body['id']}").status_code == 204
    assert client.get(f"/api/scans/{body['id']}").status_code == 404


def test_invalid_url_rejected(client):
    r = client.post("/api/scan/url", json={"url": "ftp://files.example.com", "deep": False})
    assert r.status_code == 422


def test_private_targets_not_fetched(client):
    r = client.post("/api/scan/url", json={"url": "http://127.0.0.1:8000/admin", "deep": True, "use_intel": False})
    assert r.status_code == 200
    body = r.json()
    assert any(f["id"] == "web.blocked" for f in body["findings"])
    assert body["details"]["redirects"]["chain"] == []


def test_threat_record_forces_malicious(client):
    created = client.post("/api/threats", json={"indicator": "https://totally-normal-site.com/page", "indicator_type": "url", "description": "test"})
    assert created.status_code == 201
    r = client.post("/api/scan/url", json={"url": "https://totally-normal-site.com/page", "deep": False, "use_intel": False}).json()
    assert r["risk_score"] >= 90 and any(f["id"] == "intel.local" for f in r["findings"])
    assert client.delete(f"/api/threats/{created.json()['id']}").status_code == 204


def test_email_upload(client, sample):
    files = {"file": ("msg.eml", sample("phishing_paypal.eml").encode(), "message/rfc822")}
    r = client.post("/api/scan/email/upload", files=files, data={"deep": "false", "use_intel": "false"})
    assert r.status_code == 200 and r.json()["verdict"] == "malicious"


def test_email_requires_content(client):
    assert client.post("/api/scan/email", json={}).status_code == 422


def test_model_and_intel_status(client):
    model = client.get("/api/model").json()
    assert model["metrics"]["ensemble"]["roc_auc"] > 0.9
    sources = {p["source"] for p in client.get("/api/intel/status").json()}
    assert {"virustotal", "safebrowsing", "urlhaus", "phishtank", "local"} <= sources
