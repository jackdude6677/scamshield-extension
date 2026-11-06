"""Build script to zip the Chrome extension folder.
Creates a zip file named scamshield_<version>.zip in the project root.
"""
import os
import zipfile
from pathlib import Path
import re

def get_version() -> str:
    """Extract __version__ from scamshield/__init__.py"""
    init_path = Path(__file__).resolve().parents[1] / "scamshield" / "__init__.py"
    version = "0.0.0"
    version_pattern = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
    with open(init_path, "r", encoding="utf-8") as f:
        for line in f:
            m = version_pattern.search(line)
            if m:
                version = m.group(1)
                break
    return version

def zip_extension() -> Path:
    """Create a zip archive of the extension directory.
    Returns the path to the created zip file.
    """
    root = Path(__file__).resolve().parents[1]
    ext_dir = root / "extension"
    if not ext_dir.is_dir():
        raise FileNotFoundError("extension folder not found")
    version = get_version()
    zip_name = f"scamshield_{version}.zip"
    zip_path = root / zip_name
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for folder, _, files in os.walk(ext_dir):
            for file in files:
                file_path = Path(folder) / file
                arcname = file_path.relative_to(root)
                zf.write(file_path, arcname)
    return zip_path

if __name__ == "__main__":
    created = zip_extension()
    print(f"Created {created}")
