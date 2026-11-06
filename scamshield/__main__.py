import argparse
from . import __version__
from .server import run_server

def main() -> None:
    parser = argparse.ArgumentParser(prog='scamshield', description='ScamShield CLI')
    parser.add_argument('--version', action='store_true', help='Show version')
    parser.add_argument('--run-server', action='store_true', help='Run the Flask server')
    args = parser.parse_args()
    if args.version:
        print(__version__)
    else:
        # Run server by default or when --run-server is specified
        run_server()

if __name__ == '__main__':
    main()

