import subprocess

def test_content_script_loads():
    """Ensure the content script can be required without errors."""
    result = subprocess.run(['node', '-e', "require('./extension/content.js')"],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"Node exited {result.returncode}: {result.stderr}"
