import argparse
from . import __version__

def main():
    parser = argparse.ArgumentParser(prog='scamshield', description='ScamShield CLI')
    parser.add_argument('--version', action='store_true', help='Show version')
    args = parser.parse_args()
    if args.version:
        print(__version__)

if __name__ == '__main__':
    main()
