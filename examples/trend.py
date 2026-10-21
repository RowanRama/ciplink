"""Run a controller-side trend of some tags for a few seconds and print what arrives (no tag writes)."""
import argparse
import time

from ciplink import LogixDriver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address")
    parser.add_argument("tags", nargs="+")
    parser.add_argument("--period-ms", type=float, default=10)
    parser.add_argument("--seconds", type=float, default=5)
    args = parser.parse_args()
    with LogixDriver(args.address, lazy_tags=True) as plc:
        with plc.trend(*args.tags, period_ms=args.period_ms, duration=args.seconds) as trend:
            print(trend.pens)
            while trend.running:
                time.sleep(0.25)
                batch = trend.read()
                if batch:
                    print(f"{len(batch)} samples, last {batch[-1].timestamp}: {batch[-1].values}")
        print(f"received {trend.received_samples}, dropped {trend.dropped_samples}")


if __name__ == "__main__":
    main()
