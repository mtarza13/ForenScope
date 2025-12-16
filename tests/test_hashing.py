from __future__ import annotations

from pathlib import Path

from eviforge.core.hashing import hash_file


def test_hash_file(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")

    hashes = hash_file(p)
    assert set(hashes.keys()) == {"sha256", "md5"}
    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
