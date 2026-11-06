import os
# Prepend project root to PATH so local scripts are found before virtualenv binaries
project_root = os.path.abspath(os.path.dirname(__file__))
os.environ['PATH'] = project_root + os.pathsep + os.environ.get('PATH', '')
