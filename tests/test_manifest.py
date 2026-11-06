import json
import pathlib

def test_manifest_version():
    manifest_path = pathlib.Path('extension/manifest.json')
    data = json.loads(manifest_path.read_text())
    assert data['manifest_version'] == 3
