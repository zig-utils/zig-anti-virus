#!/usr/bin/env python3
"""Regenerates the SQLite and rpmdb fixtures in this directory.

test.sqlite        a Packages table with 40 rows, one spilling into overflow pages (1 KiB pages)
wal.sqlite(+-wal)  two rows checkpointed into the file, a third committed only in the WAL
rpmdb.sqlite       an rpm 4.16+ style package database with synthetic rpm header blobs

Run from this directory: python3 make_fixtures.py
"""
import hashlib, os, shutil, sqlite3, struct

def fresh(path):
    for suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)

def test_sqlite():
    fresh("test.sqlite")
    db = sqlite3.connect("test.sqlite")
    db.execute("PRAGMA page_size = 1024")
    db.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    for i in range(39):
        db.execute("INSERT INTO Packages (blob) VALUES (?)", (bytes([i]) * (20 + i),))
    db.execute("INSERT INTO Packages (blob) VALUES (?)", (bytes((i * 7) & 0xFF for i in range(5000)),))
    db.commit()
    db.close()

def wal_sqlite():
    fresh("wal.sqlite")
    fresh("wal.tmp.sqlite")
    db = sqlite3.connect("wal.tmp.sqlite")
    db.execute("PRAGMA page_size = 1024")
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA wal_autocheckpoint = 0")
    db.execute("CREATE TABLE t (x TEXT)")
    db.execute("INSERT INTO t VALUES ('one'), ('two')")
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.execute("INSERT INTO t VALUES ('three')")
    db.commit()
    shutil.copy("wal.tmp.sqlite", "wal.sqlite")
    shutil.copy("wal.tmp.sqlite-wal", "wal.sqlite-wal")
    db.close()
    fresh("wal.tmp.sqlite")

# rpm header blob: il, dl, il index entries (tag, type, offset, count), then the data store.
NULL, CHAR, INT8, INT16, INT32, INT64, STRING, BIN, STRING_ARRAY = range(9)

def header(entries):
    index, store = b"", b""
    for tag, typ, value in entries:
        align = {INT16: 2, INT32: 4, INT64: 8}.get(typ, 1)
        store += b"\0" * ((-len(store)) % align)
        offset = len(store)
        if typ == STRING:
            store += value.encode() + b"\0"; count = 1
        elif typ == STRING_ARRAY:
            store += b"".join(v.encode() + b"\0" for v in value); count = len(value)
        elif typ == INT32:
            store += b"".join(struct.pack(">i", v) for v in value); count = len(value)
        elif typ == INT16:
            store += b"".join(struct.pack(">H", v) for v in value); count = len(value)
        else:
            raise ValueError(typ)
        index += struct.pack(">iIiI", tag, typ, offset, count)
    return struct.pack(">ii", len(entries), len(store)) + index + store

def package(name, version, release, arch, files, epoch=None):
    """files: list of (path, mode, content-or-None, config)"""
    dirs, dirindexes, basenames = [], [], []
    for path, _, _, _ in files:
        d, b = path.rsplit("/", 1)
        d += "/"
        if d not in dirs:
            dirs.append(d)
        dirindexes.append(dirs.index(d))
        basenames.append(b)
    entries = [(1000, STRING, name), (1001, STRING, version), (1002, STRING, release), (1022, STRING, arch)]
    if epoch is not None:
        entries.append((1003, INT32, [epoch]))
    if files:
        entries += [
            (1028, INT32, [len(c or b"") for _, _, c, _ in files]),
            (1030, INT16, [m for _, m, _, _ in files]),
            (1035, STRING_ARRAY, [hashlib.sha256(c).hexdigest() if c is not None else "" for _, _, c, _ in files]),
            (1037, INT32, [1 if cfg else 0 for _, _, _, cfg in files]),
            (1116, INT32, dirindexes),
            (1117, STRING_ARRAY, basenames),
            (1118, STRING_ARRAY, dirs),
            (5011, INT32, [8]),
        ]
    entries.sort(key=lambda e: e[0])
    return header(entries)

def rpmdb():
    fresh("rpmdb.sqlite")
    db = sqlite3.connect("rpmdb.sqlite")
    db.execute("PRAGMA page_size = 4096")
    db.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    pkgs = [
        package("bash", "5.2.26", "3.fc40", "x86_64", [
            ("/usr/bin/bash", 0o100755, b"bash-binary\n", False),
            ("/etc/skel/.bashrc", 0o100644, b"# rc\n", True),
            ("/usr/share/doc/bash", 0o040755, None, False),
        ]),
        package("sudo", "1.9.15", "1.p5.fc40", "x86_64", [
            ("/usr/bin/sudo", 0o104111, b"sudo-binary\n", False),
        ], epoch=1),
        package("kernel-core", "6.8.5", "301.fc40", "x86_64", [
            ("/usr/lib/modules/6.8.5-301.fc40.x86_64/kernel/drivers/net/mod%03d.ko.xz" % i, 0o100644, b"m%d" % i, False)
            for i in range(300)
        ]),
        header([(1000, STRING, "gpg-pubkey"), (1001, STRING, "a15b79cc"), (1002, STRING, "63d04c2c")]),
    ]
    for blob in pkgs:
        db.execute("INSERT INTO Packages (blob) VALUES (?)", (blob,))
    db.commit()
    db.close()

test_sqlite()
wal_sqlite()
rpmdb()
