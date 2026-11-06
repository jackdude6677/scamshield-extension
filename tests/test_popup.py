"""Tests for the extension popup UI."""

from pathlib import Path


def test_popup_contains_analyze_button():
    html_path = Path(__file__).resolve().parents[1] / "extension" / "popup.html"
    assert html_path.is_file()
    content = html_path.read_text(encoding="utf-8")
    # Ensure the button with id analyzeBtn and text Analyze exists
    assert 'id="analyzeBtn"' in content
    assert '>Analyze<' in content
