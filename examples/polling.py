"""Poll several tags over one persistent connection.

Run: python -m examples.polling 10.20.30.100 Speed Running --interval 1 --lazy-tags
"""
import argparse
import json
import math
import sys
from time import monotonic, sleep

from pycomm3 import CommError, LogixDriver


def main():
    parser = argparse.ArgumentParser(description="Poll Logix tags at a fixed interval")
    parser.add_argument("path", help="Controller IP address or CIP route")
    parser.add_argument("tags", nargs="+", help="Tags to read together")
    parser.add_argument("--interval", type=float, default=1.0, help="Poll interval in seconds")
    parser.add_argument("--lazy-tags", action="store_true", help="Load definitions on demand")
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("--interval must be positive and finite")

    try:
        with LogixDriver(args.path, lazy_tags=args.lazy_tags) as plc:
            next_poll = monotonic()
            while True:
                results = plc.read(*args.tags)
                if len(args.tags) == 1:
                    results = [results]
                print(json.dumps([result._asdict() for result in results]), flush=True)
                next_poll = max(next_poll + args.interval, monotonic())
                sleep(max(0, next_poll - monotonic()))
    except KeyboardInterrupt:
        return 0
    except CommError as err:
        print(f"Polling stopped: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
