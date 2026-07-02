from __future__ import annotations

import argparse

from src.nid.capture import DEFAULT_FIELDS, capture_to_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture network packets with TShark and export CSV features.")
    parser.add_argument("--interface", help="Network interface name or number from `tshark -D`.")
    parser.add_argument("--seconds", type=int, default=60, help="Capture duration for live interface capture.")
    parser.add_argument("--pcap", help="Existing .pcap or .pcapng file to convert.")
    parser.add_argument("--output", required=True, help="Output CSV path.")
    args = parser.parse_args()

    try:
        output = capture_to_csv(
            output=args.output,
            fields=DEFAULT_FIELDS,
            interface=args.interface,
            seconds=args.seconds,
            pcap=args.pcap,
        )
        print(f"Packet CSV written to {output}")
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
