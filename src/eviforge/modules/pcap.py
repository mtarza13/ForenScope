from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def _tshark_fields(
    *,
    tshark: str,
    pcap: Path,
    display_filter: str,
    fields: list[str],
    max_rows: int,
) -> list[dict[str, Any]]:
    cmd = [tshark, "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    proc = _run(cmd)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "tshark failed")[:2000])
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if len(rows) >= max_rows:
            break
        parts = line.split("\t")
        # Pad to field count
        while len(parts) < len(fields):
            parts.append("")
        row: dict[str, Any] = {}
        for idx, f in enumerate(fields):
            val = parts[idx].strip().strip('"')
            row[f] = val if val != "" else None
        rows.append(row)
    return rows


class PcapModule(ForensicModule):
    @property
    def name(self) -> str:
        return "pcap"

    @property
    def description(self) -> str:
        return "Analyze PCAP files with tshark (DNS/HTTP/TLS + endpoints/flows)."

    def run(self, case_id: str, evidence_id: str | None, **kwargs) -> Dict[str, Any]:
        if not evidence_id:
            raise ValueError("Missing evidence_id")

        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)

        with SessionLocal() as session:
            ev = session.get(Evidence, evidence_id)
            if not ev:
                raise ValueError(f"Evidence {evidence_id} not found")
            file_path = settings.vault_dir / ev.path

        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found at {file_path}")

        if file_path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            return {"status": "skipped", "reason": "Not a PCAP file"}

        tshark = shutil.which("tshark")
        if not tshark:
            return {"status": "skipped", "reason": "tshark not found in PATH (integration not enabled)"}

        max_rows = int(kwargs.get("max_rows", 5000))
        max_packets = int(kwargs.get("max_packets", 50000))

        # Tool version
        ver = _run([tshark, "-v"])
        tshark_version = (ver.stdout or ver.stderr).splitlines()[0] if (ver.stdout or ver.stderr) else None

        out: dict[str, Any] = {"schema_version": 1, "tshark_version": tshark_version}

        # Protocol hierarchy (text)
        phs = _run([tshark, "-r", str(file_path), "-q", "-z", "io,phs"])
        out["protocol_hierarchy"] = (phs.stdout or "")[:20000]

        # DNS, HTTP, TLS tables (bounded)
        try:
            out["dns"] = _tshark_fields(
                tshark=tshark,
                pcap=file_path,
                display_filter="dns",
                fields=["frame.time_epoch", "ip.src", "ip.dst", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.cname"],
                max_rows=max_rows,
            )
        except Exception as e:
            out["dns_error"] = str(e)

        try:
            out["http"] = _tshark_fields(
                tshark=tshark,
                pcap=file_path,
                display_filter="http",
                fields=["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "http.host", "http.request.method", "http.request.full_uri", "http.response.code", "http.user_agent"],
                max_rows=max_rows,
            )
        except Exception as e:
            out["http_error"] = str(e)

        try:
            out["tls"] = _tshark_fields(
                tshark=tshark,
                pcap=file_path,
                display_filter="tls.handshake",
                fields=["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ciphersuite", "tls.handshake.version"],
                max_rows=max_rows,
            )
        except Exception as e:
            out["tls_error"] = str(e)

        # Endpoints + flows: sample first N packets and aggregate.
        endpoints = Counter()
        flows: dict[tuple[str, str, str, str, str], int] = defaultdict(int)

        cmd = [
            tshark,
            "-r",
            str(file_path),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
            "-c",
            str(max_packets),
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ip.proto",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
        ]
        proc = _run(cmd)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                while len(parts) < 7:
                    parts.append("")
                src, dst, proto, tcp_s, tcp_d, udp_s, udp_d = parts[:7]
                src = src.strip()
                dst = dst.strip()
                if src:
                    endpoints[src] += 1
                if dst:
                    endpoints[dst] += 1
                proto_name = {"6": "tcp", "17": "udp"}.get(proto.strip(), proto.strip() or "unknown")
                sport = (tcp_s or udp_s).strip()
                dport = (tcp_d or udp_d).strip()
                if src and dst:
                    flows[(src, dst, proto_name, sport or "", dport or "")] += 1
        else:
            out["flows_error"] = (proc.stderr or proc.stdout or "tshark flow sampling failed")[:2000]

        out["endpoints"] = [{"ip": ip, "packets_sampled": int(cnt)} for ip, cnt in endpoints.most_common(2000)]
        out["connections"] = [
            {"src": k[0], "dst": k[1], "proto": k[2], "src_port": k[3] or None, "dst_port": k[4] or None, "packets_sampled": int(v)}
            for k, v in sorted(flows.items(), key=lambda kv: (-kv[1], kv[0]))[:2000]
        ]
        out["sampling"] = {"max_packets": max_packets, "max_rows": max_rows}

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "pcap"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}.json"
        output_file.write_text(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return {
            "status": "success",
            "output_file": str(output_file),
            "dns_rows": len(out.get("dns", []) or []),
            "http_rows": len(out.get("http", []) or []),
            "tls_rows": len(out.get("tls", []) or []),
        }

