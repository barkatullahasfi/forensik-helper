"""
Ekstraksi JA3/JA3S — sidik jari cara klien/server menegosiasikan TLS.

Berguna justru ketika isi traffic TIDAK bisa dibaca: JA3 tetap terlihat karena
Client Hello dikirim sebelum enkripsi aktif.
"""
from collections import Counter

from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, to_utc


def has_ja3_support() -> bool:
    """
    tshark >= 4.2 punya field bawaan `tls.handshake.ja3`. Versi lama tidak, dan
    tanpa pengecekan ini filter-nya ditolak dan seluruh analisis gagal -- bukan
    cuma modul ini.
    """
    from . import tools
    from .tools import run
    out = run([tools.resolve("tshark"), "-G", "fields"], timeout=120, check=False)
    return "\tja3\t" in out or "tls.handshake.ja3" in out


def extract_ja3_fingerprints(pcap_path, internal_ip: str,
                             evidence: EvidenceLog | None = None) -> list[dict]:
    """JA3 (client hello) dan JA3S (server hello) per sesi TLS, plus SNI-nya."""
    if evidence is None:
        evidence = EvidenceLog()
    if not has_ja3_support():
        return [{"skipped": "tshark versi ini tidak punya field tls.handshake.ja3 -- "
                            "perlu tshark >= 4.2 atau plugin Lua ja3.lua"}]

    clients = run_tshark_fields(
        pcap_path, f"tls.handshake.type==1 && ip.src=={internal_ip}",
        ["frame.time_epoch", "tcp.stream", "ip.dst",
         "tls.handshake.ja3", "tls.handshake.extensions_server_name"])
    servers = {r["tcp.stream"].split(",")[0]: r["tls.handshake.ja3s"].split(",")[0]
               for r in run_tshark_fields(pcap_path, "tls.handshake.type==2",
                                          ["tcp.stream", "tls.handshake.ja3s"])}

    results = []
    for row in clients:
        stream = row["tcp.stream"].split(",")[0]
        ja3 = row["tls.handshake.ja3"].split(",")[0]
        sni = row["tls.handshake.extensions_server_name"].split(",")[0]
        results.append({
            "tcp_stream": _int(stream),
            "time_utc": to_utc(_float(row["frame.time_epoch"])),
            "destination_ip": row["ip.dst"].split(",")[0],
            "sni": sni or None,
            "ja3": ja3 or None,
            "ja3s": servers.get(stream),
            "evidence_query": f"tcp.stream=={stream} && tls.handshake.type==1",
        })
    return results


def summarize_ja3(fingerprints: list[dict]) -> list[dict]:
    """
    Kelompokkan per JA3.

    Satu JA3 yang dipakai ke BANYAK destinasi berbeda menarik: itu satu program
    yang menghubungi banyak server. Kalau destinasinya campuran domain tak
    dikenal, kandidat kuat untuk diperiksa.
    """
    groups: dict[str, dict] = {}
    for item in fingerprints:
        if not item.get("ja3"):
            continue
        entry = groups.setdefault(item["ja3"], {"ja3": item["ja3"], "sessions": 0,
                                                "destinations": set(), "sni": set()})
        entry["sessions"] += 1
        entry["destinations"].add(item["destination_ip"])
        if item.get("sni"):
            entry["sni"].add(item["sni"])
    return sorted(
        ({"ja3": g["ja3"], "session_count": g["sessions"],
          "distinct_destinations": len(g["destinations"]),
          "server_names": sorted(g["sni"])[:12]} for g in groups.values()),
        key=lambda g: -g["session_count"])


def lookup_ja3_reputation(fingerprints: list[dict], checker,
                          evidence: EvidenceLog | None = None) -> list[dict]:
    """Cross-check tiap JA3 unik ke SSLBL lewat ThreatFeedChecker (feed lokal)."""
    if evidence is None:
        evidence = EvidenceLog()
    hits = []
    for ja3 in {f["ja3"] for f in fingerprints if f.get("ja3")}:
        result = checker.check_ja3(ja3)
        if result["is_known_malicious"]:
            query = f'tls.handshake.ja3 == "{ja3}"'
            hits.append({**result, "evidence_query": query})
            evidence.track("known_malicious_ja3", query, ja3,
                           note="Cocok dengan JA3 blacklist SSLBL (abuse.ch)")
    return hits


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
