"""Measure a single-worker clamd on verified, benign corpus directories."""

import argparse
import os
from pathlib import Path
import socket
import statistics
import time


def request(socket_path, command):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(120)
        client.connect(socket_path)
        client.sendall(b'z' + command + b'\0')
        with client.makefile('rb') as response:
            result = response.read(8192)
    if not result.endswith(b'\0'):
        raise ValueError(f'incomplete clamd response: {result!r}')
    return result


def measure(socket_path, directory, rounds):
    files = []
    byte_count = 0
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        size = path.stat().st_size
        if not size:
            continue
        files.append(os.fsencode(path.resolve()))
        byte_count += size
    if not files:
        raise ValueError(f'empty corpus: {directory}')

    rates = []
    for round_no in range(1, rounds + 1):
        start = time.monotonic()
        for name in files:
            response = request(socket_path, b'SCAN ' + name)
            if response != name + b': OK\0':
                raise ValueError(f'unexpected clamd response: {response!r}')
        seconds = time.monotonic() - start
        rates.append(byte_count / 1_000_000 / seconds)
        print(f'{directory.name} round {round_no}: {len(files)} files, {byte_count} bytes, '
              f'{seconds:.2f} s, {rates[-1]:.1f} MB/s', flush=True)
    print(f'{directory.name}: best {max(rates):.1f} MB/s, median {statistics.median(rates):.1f} MB/s')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('corpus', nargs='+', type=Path)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    if request(args.socket, b'PING') != b'PONG\0':
        raise ValueError('clamd did not respond to PING')
    print(request(args.socket, b'VERSION')[:-1].decode(), flush=True)
    for directory in args.corpus:
        measure(args.socket, directory, args.rounds)


if __name__ == '__main__':
    main()
