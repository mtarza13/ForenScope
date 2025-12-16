from __future__ import annotations

from pathlib import Path

from eviforge.core.custody import append_entry, verify_chain


def test_custody_hashchain_roundtrip(tmp_path: Path):
    log_path = tmp_path / "chain_of_custody.log"

    append_entry(log_path, actor="tester", action="case.create", details={"case": "X"})
    append_entry(log_path, actor="tester", action="evidence.ingest", details={"label": "E1"})

    ok, msg = verify_chain(log_path)
    assert ok, msg


def test_custody_hashchain_tamper_detected(tmp_path: Path):
    log_path = tmp_path / "chain_of_custody.log"
    append_entry(log_path, actor="tester", action="case.create", details={"case": "X"})

    # Tamper with the file
    data = log_path.read_text(encoding="utf-8").replace("case.create", "case.CORRUPTED")
    log_path.write_text(data, encoding="utf-8")

    ok, msg = verify_chain(log_path)
    assert not ok
    assert "mismatch" in msg
