"""Generate the deterministic corpus verified by zig build io-check."""

import argparse
import os
from pathlib import Path
import struct


def generate(root: Path, count: int) -> None:
    root.mkdir()
    for shard in range((count + 999) // 1000):
        directory = root / f"{shard:03d}"
        directory.mkdir()
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            for slot in range(min(1000, count - shard * 1000)):
                number = shard * 1000 + slot
                payload = struct.pack("<Q", number) * 512
                file = os.open(
                    f"{slot:03d}", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=directory_fd,
                )
                try:
                    if os.write(file, payload) != len(payload):
                        raise OSError("short fixture write")
                finally:
                    os.close(file)
        finally:
            os.close(directory_fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("count", type=int)
    args = parser.parse_args()
    if not 0 < args.count <= 1_000_000:
        parser.error("count must be between 1 and 1,000,000")
    generate(args.root, args.count)
    print(f"{args.count:,} files created")
