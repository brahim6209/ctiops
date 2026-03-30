"""opencti_mock.py — Simule l'API OpenCTI localement (sans Docker)"""
from flask import Flask, request, jsonify
from datetime import datetime

app   = Flask(__name__)
STORE = []

@app.route("/graphql", methods=["POST"])
def graphql():
    data = request.json or {}
    obj  = {"id": len(STORE)+1, "received_at": datetime.now().isoformat(), "preview": str(data)[:150]}
    STORE.append(obj)
    print(f"[OpenCTI MOCK] Objet STIX reçu #{len(STORE)} — {datetime.now().strftime('%H:%M:%S')}")
    return jsonify({"data": {"stixObjectOrStixRelationship": {"id": str(len(STORE))}}})

@app.route("/api/health")
def health():
    return jsonify({"status": "alive", "version": "mock-6.2.0", "objects_received": len(STORE)})

@app.route("/api/objects")
def objects():
    return jsonify({"total": len(STORE), "objects": STORE[-20:]})

@app.route("/")
def index():
    return f"""<h2>OpenCTI Mock — CTI Cloud-Native</h2>
    <p>Objets reçus : <b>{len(STORE)}</b></p>
    <p><a href='/api/health'>Health</a> | <a href='/api/objects'>Objets</a></p>"""

if __name__ == "__main__":
    print("="*45)
    print("  OpenCTI MOCK — http://localhost:8080")
    print("  Simule l'API OpenCTI pour la démo")
    print("="*45)
    app.run(host="0.0.0.0", port=8080, debug=False)
