"""Integration test for ScamShield extension components."""

import json
import subprocess
from pathlib import Path


def test_manifest_version():
    """Ensure the manifest declares version 3."""
    manifest_path = Path(__file__).resolve().parents[1] / "extension" / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data.get("manifest_version") == 3


def test_content_script_loads():
    """Require the content script via Node to ensure no syntax errors."""
    result = subprocess.run(
        ["node", "-e", "require('./extension/content.js')"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Node exited {result.returncode}: {result.stderr}"


def test_popup_contains_analyze_button():
    """Check that the popup HTML includes the Analyze button."""
    html_path = Path(__file__).resolve().parents[1] / "extension" / "popup.html"
    content = html_path.read_text(encoding="utf-8")
    assert 'id="analyzeBtn"' in content
    assert '>Analyze<' in content
