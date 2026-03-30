"""webhook_listener.py — Récepteur événements GitHub Actions"""
import hmac, hashlib, json, os
from fastapi import FastAPI, Request, HTTPException, Header
from dotenv import load_dotenv
from database import init_db, insert_incident, insert_ioc
from cicd_rules import analyze_event
from ml_models import predict_severity, detect_anomaly

load_dotenv()
app    = FastAPI(title="CTI Webhook Listener")
SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "test_secret_local")

def verify_sig(payload: bytes, sig: str) -> bool:
    expected = "sha256=" + hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)

@app.on_event("startup")
def startup():
    init_db()
    print("[WEBHOOK] Listener démarré sur port 8000")

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(default=None),
    x_github_event: str = Header(default="unknown"),
):
    if x_github_event in ("check_run","check_suite","status","pull_request",
                           "create","delete","fork","watch","star","release",
                           "repository","member","public","gollum","deployment",
                           "deployment_status","page_build","project","label",
                           "milestone","issue_comment","issues","discussion"):
        return {"status": "ignored", "event": x_github_event}
    body = await request.body()
    if x_hub_signature_256 and not verify_sig(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Signature invalide")
    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="JSON invalide")

    incident = analyze_event(payload, x_github_event)
    if incident:
        # Enrichir avec ML
        ml = predict_severity(incident["event_type"], incident["source"], incident["triggered_at"])
        incident["ml_severity"] = ml["severity"]
        anom = detect_anomaly(60.0, 0.1 if incident["severity"]=="LOW" else 0.9, 10, 12)
        incident["anomaly_score"] = anom["anomaly_score"]

        incident_id = insert_incident(incident)
        for ioc in incident.get("iocs", []):
            insert_ioc({"type": ioc["type"], "value": ioc["value"],
                        "source": str(incident_id), "tlp": incident["tlp"]})
        print(f"[WEBHOOK] Incident #{incident_id} — {incident['event_type']} ({incident['severity']}) ML:{incident['ml_severity']}")

    return {"status": "received", "event": x_github_event}

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
