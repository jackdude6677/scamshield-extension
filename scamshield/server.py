"""Flask server for ScamShield backend proxy.
Provides health check, lookup, and analysis endpoints.
"""

from __future__ import annotations

from flask import Flask, jsonify, request

from .detection import is_suspicious

app = Flask(__name__)

@app.get("/health")
def health() -> str:
    return "OK"

@app.get("/lookup")
def lookup():
    hash_prefix = request.args.get("hash")
    if not hash_prefix:
        return jsonify({"error": "Missing 'hash' parameter"}), 400
    # mock verdict
    verdict = "malicious" if hash_prefix.lower().startswith("bad") else "clean"
    return jsonify({"verdict": verdict})

@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    # simple analysis: flag suspicious URLs
    if url and is_suspicious(url):
        return jsonify({"risk": "high"})
    return jsonify({"risk": "low"})

def run_server(host: str = "0.0.0.0", port: int = 5000) -> None:
    app.run(host=host, port=port)
