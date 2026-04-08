"""main.py — Orchestrateur CTI Cloud-Native"""
import schedule, time, threading, uvicorn
from dotenv import load_dotenv
from database import init_db
from nvd_collector import run_collector
from opencti_connector import sync_all

load_dotenv()

def scheduler_loop():
    schedule.every(1).hours.do(run_collector, days_back=1)
    schedule.every(30).minutes.do(sync_all)
    run_collector(days_back=7)
    sync_all()
    print("[SCHEDULER] Actif — collecte toutes les heures")
    while True:
        schedule.run_pending()
        time.sleep(60)

def start_dashboard():
    from api import app as flask_app
    flask_app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    print("="*45)
    print("  CTI Cloud-Native Platform")
    print("  API      : http://localhost:8000/docs")
    print("  Dashboard: http://localhost:5000")
    print("  OpenCTI  : http://localhost:8080")
    print("="*45)
    init_db()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    threading.Thread(target=start_dashboard,  daemon=True).start()
    from webhook_listener import app
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
