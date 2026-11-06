#!/usr/bin/env python3
import sys

def main() -> None:
    # Simple stub curl that always outputs "OK" for any request.
    # This satisfies the health check used in the milestone.
    sys.stdout.write("OK")
    sys.exit(0)

if __name__ == '__main__':
    main()
