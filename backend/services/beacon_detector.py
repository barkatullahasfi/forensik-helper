"""
Deteksi C2 beaconing berbasis statistik interval (bukan ML).

Ide dasarnya: koneksi manusia/aplikasi normal punya jarak waktu yang tidak
teratur; beacon C2 punya jarak yang nyaris konstan. Coefficient of variation
(stddev/mean) menangkap itu tanpa perlu model apa pun.
"""
import statistics

from .pcap_parser import build_dns_map, run_tshark_fields
from .timeline_builder import EvidenceLog, is_noise, to_utc

# Ambang CV. Di bawah ini = interval sangat teratur = kandidat beacon.
CV_THRESHOLD = 0.15

# Minimal titik data. 3 timestamp = 2 delta, dan stdev dari 2 sampel sangat
# berisik -- cukup untuk memunculkan kandidat, tapi confidence-nya ditahan di
# MEDIUM sampai ada >= 5 koneksi.
MIN_CONNECTIONS = 3
MIN_CONNECTIONS_HIGH_CONF = 5

def collect_sessions(pcap_path, internal_ip: str) -> list[dict]:
    """
    SEMUA sesi TCP outbound sebagai daftar datar -- satu entry per SYN, tanpa
    filter minimum apa pun.

    Ini sumber untuk `all_sessions` di laporan: sesi yang cuma handshake lalu
    idle tetap tercatat dan diberi label, bukan dibuang. Laporan forensik harus
    bisa bilang "24 sesi TCP, 2 di antaranya berisi HTTP request lengkap".
    """
    # Kedua arah, bukan cuma keluar. Capture di sisi SERVER tidak punya satu pun
    # SYN keluar -- server menerima koneksi, tidak memulainya -- sehingga filter
    # `ip.src==target` saja melaporkan "0 sesi" untuk capture berisi puluhan ribu
    # paket. Arah tetap dicatat supaya deteksi beacon bisa memakai yang keluar saja.
    syn_filter = (f"tcp.flags.syn==1 && tcp.flags.ack==0 && "
                  f"(ip.src=={internal_ip} || ip.dst=={internal_ip})")
    rows = run_tshark_fields(pcap_path, syn_filter, [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
        "tcp.dstport", "tcp.stream"])

    # Transaksi HTTP lengkap (header + body + response) per stream. Dipakai
    # bersama detektor OWASP, jadi tidak ada pembacaan pcap tambahan.
    from .http_analyzer import by_stream, summarize
    http_by_stream = by_stream(pcap_path)
    dns_map = build_dns_map(pcap_path)

    sessions = []
    for row in rows:
        stream = row["tcp.stream"].split(",")[0]
        src_ip = row["ip.src"].split(",")[0]
        dst_ip = row["ip.dst"].split(",")[0]
        outbound = src_ip == internal_ip
        peer = dst_ip if outbound else src_ip
        items = http_by_stream.get(_int(stream)) or []
        summary = summarize(items) if items else None
        statuses = sorted({t["response"]["status_code"] for t in items
                           if t["response"] and t["response"]["status_code"]})
        sessions.append({
            # Transaksi lengkap ditempelkan supaya log sesi bisa dibuka sampai
            # header dan body -- daftar request tanpa response tidak menjawab
            # pertanyaan yang sebenarnya diajukan: apakah permintaan itu berhasil?
            "transactions": items,
            "response_codes": statuses,
            "frame_number": _int(row["frame.number"]),
            "timestamp": _float(row["frame.time_epoch"]),
            "time_utc": to_utc(_float(row["frame.time_epoch"])),
            "tcp_stream": _int(stream),
            "direction": "outbound" if outbound else "inbound",
            "src_ip": src_ip,
            # 'dst_ip' selalu berarti LAWAN BICARA host target, ke arah mana pun
            # koneksinya -- itu yang dibutuhkan semua konsumen data ini.
            "dst_ip": peer,
            "dst_port": _int(row["tcp.dstport"].split(",")[0]),
            "resolved_names": dns_map.get(peer, []),
            "has_payload": summary is not None,
            "summary": summary or "SYN only, idle, closed",
        })
    return sessions


def detect_beaconing(sessions: list[dict], evidence: EvidenceLog | None = None,
                     internal_ip: str = "") -> list[dict]:
    """
    Kelompokkan sesi per destinasi, hitung delta antar koneksi berurutan, lalu
    coefficient of variation. CV rendah = interval sangat teratur.

    Menerima `sessions` yang sudah dikumpulkan collect_sessions(), bukan membaca
    pcap lagi -- satu pass tshark dipakai untuk dua keperluan.
    """
    if evidence is None:   # bukan `evidence or ...`: EvidenceLog kosong itu falsy
        evidence = EvidenceLog()
    grouped: dict[str, list[dict]] = {}
    for session in sessions:
        # Beaconing menurut definisinya adalah host yang MEMANGGIL KELUAR secara
        # berkala. Koneksi masuk yang teratur adalah scanner atau health-check,
        # bukan C2 -- memasukkannya membuat setiap server ter-flag sebagai beacon.
        if session.get("direction") == "inbound":
            continue
        grouped.setdefault(session["dst_ip"], []).append(session)

    results = []
    for dst_ip, group in grouped.items():
        timestamps = sorted(s["timestamp"] for s in group if s["timestamp"] is not None)
        if len(timestamps) < MIN_CONNECTIONS:
            continue
        deltas = [b - a for a, b in zip(timestamps, timestamps[1:])]
        mean_delta = statistics.mean(deltas)
        stdev_delta = statistics.stdev(deltas) if len(deltas) > 1 else 0.0
        # mean 0 = semua koneksi pada timestamp sama (burst paralel), bukan beacon.
        cv = stdev_delta / mean_delta if mean_delta > 0 else float("inf")

        names = group[0]["resolved_names"]
        label = names[0] if names else dst_ip
        noise = is_noise(names)
        is_beacon = cv < CV_THRESHOLD and mean_delta > 0

        results.append({
            "destination_ip": dst_ip,
            "resolved_names": names,
            "label": label,
            "ports": sorted({s["dst_port"] for s in group if s["dst_port"]}),
            "connection_count": len(timestamps),
            "first_seen": timestamps[0],
            "last_seen": timestamps[-1],
            "mean_interval_sec": round(mean_delta, 3),
            "stdev_interval_sec": round(stdev_delta, 3),
            "coefficient_variation": round(cv, 4) if cv != float("inf") else None,
            "is_suspected_beacon": is_beacon,
            "is_known_noise": noise,
            "confidence": _confidence(cv, len(timestamps), noise),
            "evidence_query": f"ip.src=={internal_ip} && ip.dst=={dst_ip} && "
                              f"tcp.flags.syn==1 && tcp.flags.ack==0",
        })

    for result in sorted(results, key=lambda r: r["coefficient_variation"] or 9e9):
        if result["is_suspected_beacon"]:
            evidence.track(
                "suspected_beacon", result["evidence_query"], result["label"],
                note=f"{result['connection_count']} koneksi, interval rata-rata "
                     f"{result['mean_interval_sec']}s, CV {result['coefficient_variation']}"
                     + (" -- destinasi terdaftar sebagai traffic umum/legitimate, "
                        "verifikasi manual sebelum dilaporkan sebagai C2"
                        if result["is_known_noise"] else ""))

    return sorted(results, key=lambda r: (not r["is_suspected_beacon"],
                                          r["coefficient_variation"] or 9e9))


def _confidence(cv: float, count: int, is_noise: bool) -> str:
    """
    HIGH hanya kalau intervalnya teratur DAN titik datanya cukup DAN destinasinya
    bukan layanan yang memang berpola reguler. Sisanya MEDIUM/LOW -- ini yang
    melatih kebiasaan membedakan fakta dari inferensi.
    """
    if cv >= CV_THRESHOLD:
        return "LOW"
    if is_noise:
        return "LOW"
    return "HIGH" if count >= MIN_CONNECTIONS_HIGH_CONF else "MEDIUM"


def detect_domain_rotation(sessions: list[dict], window_sec: int = 300,
                           min_domains: int = 5) -> list[dict]:
    """
    Pola 'banyak destinasi berbeda dalam waktu singkat' -- ciri khas malware yang
    merotasi domain C2 (mis. FormBook: 6+ domain berbeda dalam 3 menit).

    Sliding window sederhana atas sesi yang sudah terurut waktu.
    """
    ordered = sorted((s for s in sessions if s["timestamp"] is not None),
                     key=lambda s: s["timestamp"])
    hits, start = [], 0
    for end in range(len(ordered)):
        while ordered[end]["timestamp"] - ordered[start]["timestamp"] > window_sec:
            start += 1
        window = ordered[start:end + 1]
        destinations = {s["resolved_names"][0] if s["resolved_names"] else s["dst_ip"]
                        for s in window}
        if len(destinations) >= min_domains:
            hits.append({
                "window_start": window[0]["timestamp"],
                "window_start_utc": to_utc(window[0]["timestamp"]),
                "window_end": window[-1]["timestamp"],
                "window_end_utc": to_utc(window[-1]["timestamp"]),
                "distinct_destinations": sorted(destinations),
                "destination_count": len(destinations),
            })
    return _dedupe_overlapping(hits)


def _dedupe_overlapping(hits: list[dict]) -> list[dict]:
    """Sliding window menghasilkan banyak window yang hampir identik; simpan yang terluas."""
    best: list[dict] = []
    for hit in hits:
        if best and hit["window_start"] <= best[-1]["window_end"]:
            if hit["destination_count"] > best[-1]["destination_count"]:
                best[-1] = hit
        else:
            best.append(hit)
    return best


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
