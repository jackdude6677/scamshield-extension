"""Flask server for ScamShield backend proxy.
Provides health check and a minimal threat lookup endpoint.
The real implementation would call Google Safe Browsing API using an
API key stored in the environment variable ``SAFE_BROWSING_API_KEY``.
For this milestone we return a mocked verdict based on the provided
hash prefix.
"""

from __future__ import annotations

import os
from typing import Dict

from flask import Flask, jsonify, request

app = Flask(__name__)

# Simple health check
@app.get("/health")
def health() -> str:
    return "OK"


def _mock_verdict(hash_prefix: str) -> Dict[str, str]:
    """Return a fake verdict.

    In a real implementation this would query the Google Safe Browsing
    API. Here we simply mark any hash that starts with ``"bad"`` as
    ``malicious`` and everything else as ``clean``.
    """
    if hash_prefix.lower().startswith("bad"):
        return {"verdict": "malicious"}
    return {"verdict": "clean"}


@app.get("/lookup")
def lookup() -> "flask.Response":
    """Lookup a URL hash prefix.

    Query parameter ``hash`` is required. Returns JSON with a ``verdict``
    field. If the required parameter is missing a 400 error is returned.
    """
    hash_prefix = request.args.get("hash")
    if not hash_prefix:
        return jsonify({"error": "Missing 'hash' parameter"}), 400
    # In a real implementation we would use the API key:
    # api_key = os.getenv("SAFE_BROWSING_API_KEY")
    # ... perform request ...
    result = _mock_verdict(hash_prefix)
    return jsonify(result)


def run_server(host: str = "0.0.0.0", port: int = 5000) -> None:
    """Entry point to run the Flask development server.
    """
    app.run(host=host, port=port)

