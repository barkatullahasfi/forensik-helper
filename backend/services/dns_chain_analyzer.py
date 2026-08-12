"""
Analisis rantai DNS — memisahkan domain 'anomali' dari noise, dan menemukan
celah waktu tanpa aktivitas network.

Tujuannya merekonstruksi delivery chain (search -> redirector -> host payload),
bukan mendaftar semua DNS query.
"""
from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, is_noise, to_utc


def get_dns_queries(pcap_path, internal_ip: str) -> list[dict]:
    """Semua DNS query dari host, terurut waktu."""
    display_filter = f"dns.flags.response==0 && ip.src=={internal_ip}"
    rows = run_tshark_fields(pcap_path, display_filter,
                             ["frame.number", "frame.time_epoch", "dns.qry.name"])
    queries, seen = [], set()
    for row in rows:
        for name in row["dns.qry.name"].split(","):
            name = name.strip().rstrip(".")
            # Query SRV/service ('_ldap._tcp...') dan reverse lookup bukan bagian
            # dari delivery chain -- itu mekanik domain, bukan pilihan pengguna.
            if not name or name.startswith("_") or name.endswith(".in-addr.arpa"):
                continue
            timestamp = _float(row["frame.time_epoch"])
            if (name, timestamp) in seen:
                continue
            seen.add((name, timestamp))
            queries.append({
                "frame_number": _int(row["frame.number"]),
                "timestamp": timestamp,
                "time_utc": to_utc(timestamp),
                "domain": name,
                "is_noise": is_noise([name]),
            })
    return sorted(queries, key=lambda q: q["timestamp"] or 0)


def build_dns_chain(pcap_path, internal_ip: str, around_timestamp: float | None = None,
                    window_sec: int = 60, evidence: EvidenceLog | None = None,
                    queries: list[dict] | None = None) -> list[dict]:
    """
    Domain anomali (non-noise) dalam jendela waktu tertentu, terurut waktu --
    kandidat delivery chain.

    Domain noise TIDAK dibuang dari data mentah (lihat get_dns_queries), hanya
    tidak masuk kandidat. Yang dibuang total tidak bisa diperiksa ulang.
    """
    if evidence is None:
        evidence = EvidenceLog()
    # Terima hasil query yang sudah diambil pemanggil; membaca ulang pcap untuk
    # data yang sama adalah satu pass penuh yang terbuang.
    if queries is None:
        queries = get_dns_queries(pcap_path, internal_ip)
    if around_timestamp is not None:
        queries = [q for q in queries
                   if q["timestamp"] and abs(q["timestamp"] - around_timestamp) <= window_sec]

    chain, seen = [], set()
    for query in queries:
        if query["is_noise"] or query["domain"] in seen:
            continue
        seen.add(query["domain"])
        chain.append(query)

    for link in chain:
        evidence.track("dns_anomalous_domain",
                       f'dns.qry.name == "{link["domain"]}"', link["domain"],
                       note=f"Query pertama {link['time_utc']} (frame {link['frame_number']}). "
                            "Tidak cocok daftar domain umum -- kandidat delivery chain")
    return chain


def calculate_gap_analysis(chain: list[dict], min_gap_sec: int = 30) -> list[dict]:
    """
    Celah waktu tanpa aktivitas DNS di antara event chain.

    Gap besar sering berarti ada proses LOKAL yang berjalan (ekstrak arsip,
    user mengklik installer, malware menunggu sandbox timeout) yang memang tidak
    meninggalkan jejak di network. Ini dugaan yang perlu dikonfirmasi dari disk
    atau memory, bukan kesimpulan -- itu sebabnya labelnya 'kemungkinan'.
    """
    gaps = []
    for before, after in zip(chain, chain[1:]):
        if not (before["timestamp"] and after["timestamp"]):
            continue
        delta = after["timestamp"] - before["timestamp"]
        if delta >= min_gap_sec:
            gaps.append({
                "after_domain": before["domain"],
                "before_domain": after["domain"],
                "gap_seconds": round(delta, 1),
                "gap_start_utc": before["time_utc"],
                "gap_end_utc": after["time_utc"],
                "note": "Tidak ada query domain anomali selama rentang ini -- "
                        "kemungkinan aktivitas lokal (ekstraksi/eksekusi) yang "
                        "tidak tercatat di traffic. Perlu konfirmasi dari disk/RAM",
            })
    return gaps


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
