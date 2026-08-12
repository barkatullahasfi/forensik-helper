"""
Deteksi port/protokol tidak wajar.

Dua pertanyaan berbeda:
1. Apakah ada traffic ke port yang jarang dipakai aplikasi legitimate?
2. Apakah ada yang mengaku HTTPS (port 443) tapi bukan TLS sungguhan?
"""
from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog

# Port yang sering dipakai C2/RAT. Daftar ini menandai, bukan membuktikan --
# banyak aplikasi internal memang pakai port tinggi.
SUSPICIOUS_PORTS = {
    1337: "umum dipakai backdoor/CTF", 4444: "default Metasploit/meterpreter",
    4445: "varian Metasploit", 5555: "ADB / beberapa RAT", 6666: "IRC bot / RAT",
    6667: "IRC (C2 klasik)", 7777: "beberapa RAT", 8080: "HTTP proxy alternatif",
    8443: "HTTPS alternatif", 9001: "Tor ORPort / Cobalt Strike", 9002: "Cobalt Strike default",
    31337: "backdoor klasik (elite)", 50050: "Cobalt Strike team server",
}

# Port yang wajar dipakai host Windows biasa -- tidak perlu dilaporkan.
COMMON_PORTS = {80, 443, 53, 88, 123, 135, 137, 138, 139, 389, 445, 464, 636,
                993, 995, 3268, 3269, 5353, 5355}


def detect_nonstandard_c2_ports(pcap_path, internal_ip: str,
                                evidence: EvidenceLog | None = None) -> list[dict]:
    """Koneksi outbound ke port yang tidak lazim untuk host Windows biasa."""
    if evidence is None:
        evidence = EvidenceLog()
    rows = run_tshark_fields(
        pcap_path, f"tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src=={internal_ip}",
        ["frame.time_epoch", "ip.dst", "tcp.dstport"])

    grouped: dict[tuple, int] = {}
    for row in rows:
        port = _int(row["tcp.dstport"].split(",")[0])
        dst = row["ip.dst"].split(",")[0]
        if port is None or port in COMMON_PORTS:
            continue
        grouped[(dst, port)] = grouped.get((dst, port), 0) + 1

    findings = []
    for (dst, port), count in sorted(grouped.items(), key=lambda kv: -kv[1]):
        known = SUSPICIOUS_PORTS.get(port)
        # Port ephemeral tinggi tanpa reputasi khusus terlalu berisik untuk
        # dilaporkan satu per satu; hanya port berreputasi atau <1024 yang naik.
        if not known and port >= 1024:
            continue
        findings.append({
            "destination_ip": dst, "port": port, "connection_count": count,
            "reason": known or "port sistem non-standar untuk traffic outbound",
            "confidence": "MEDIUM" if known else "LOW",
            "evidence_query": f"ip.src=={internal_ip} && ip.dst=={dst} && tcp.dstport=={port}",
        })
        evidence.track("nonstandard_c2_port", findings[-1]["evidence_query"],
                       f"{dst}:{port}",
                       note=f"{count} koneksi. {known or 'port non-standar'}")
    return findings


# Port -> layanan. Dipakai menamai apa yang diekspos host, bukan menilai bahaya.
WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 135: "MSRPC endpoint mapper", 139: "NetBIOS session",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos password",
    636: "LDAPS", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 8080: "HTTP alternatif",
    8443: "HTTPS alternatif", 27017: "MongoDB",
}


def map_exposed_services(sessions: list[dict], internal_ip: str,
                         evidence: EvidenceLog | None = None) -> list[dict]:
    """
    Port pada host target yang MENERIMA koneksi masuk, beserta siapa saja yang
    menghubunginya.

    Ini menjawab pertanyaan pertama pada capture sisi server: "apa yang
    sebenarnya diserang?" Daftar sesi mentah tidak menjawabnya -- 1075 baris
    koneksi masuk perlu diringkas jadi "layanan X di port Y, dihubungi Z kali
    oleh N host".

    Dihitung dari sesi yang SUDAH dikumpulkan, tanpa membaca ulang pcap.
    """
    if evidence is None:
        evidence = EvidenceLog()
    inbound = [s for s in sessions if s.get("direction") == "inbound" and s.get("dst_port")]
    by_port: dict[int, list[dict]] = {}
    for session in inbound:
        by_port.setdefault(session["dst_port"], []).append(session)

    services = []
    for port, group in sorted(by_port.items(), key=lambda kv: -len(kv[1])):
        peers = sorted({s["dst_ip"] for s in group})
        with_payload = sum(1 for s in group if s["has_payload"])
        services.append({
            "port": port,
            "service": WELL_KNOWN.get(port, "tidak dikenal"),
            "is_well_known": port in WELL_KNOWN,
            "connection_count": len(group),
            "sessions_with_payload": with_payload,
            "distinct_sources": peers,
            "first_seen_utc": min((s["time_utc"] for s in group if s["time_utc"]), default=None),
            "evidence_query": f"ip.dst=={internal_ip} && tcp.dstport=={port} && "
                              "tcp.flags.syn==1 && tcp.flags.ack==0",
        })
        evidence.track(
            "exposed_service", services[-1]["evidence_query"],
            f"port {port}/tcp ({services[-1]['service']})",
            note=f"{len(group)} koneksi masuk dari {len(peers)} sumber "
                 f"({', '.join(peers[:4])}), {with_payload} berisi payload. "
                 + ("Port tidak dikenal -- perlu dicek proses mana yang mendengarkannya"
                    if port not in WELL_KNOWN else ""))
    return services


def detect_port_scan(sessions: list[dict], internal_ip: str, min_ports: int = 8,
                     window_sec: int = 120, evidence: EvidenceLog | None = None) -> list[dict]:
    """
    Banyak port BERBEDA disentuh satu sumber dalam waktu singkat, masing-masing
    hanya sekali atau dua kali.

    Tanpa deteksi ini, port scan tampil sebagai deretan panjang "port 113: 1
    koneksi, port 587: 1 koneksi, ..." yang harus disimpulkan sendiri oleh
    pembaca. Padahal justru itu yang biasanya ditanyakan: berapa port yang
    dipindai, dari mana, dan kapan.

    Yang membedakan scan dari pemakaian normal bukan jumlah portnya saja, tapi
    bahwa hampir semuanya hanya disentuh SEKALI -- klien sungguhan menyambung
    ulang, scanner tidak.
    """
    if evidence is None:
        evidence = EvidenceLog()
    inbound = sorted((s for s in sessions
                      if s.get("direction") == "inbound" and s.get("dst_port")
                      and s.get("timestamp") is not None),
                     key=lambda s: s["timestamp"])

    by_source: dict[str, list[dict]] = {}
    for session in inbound:
        by_source.setdefault(session["dst_ip"], []).append(session)

    findings = []
    for source, group in by_source.items():
        best = None
        start = 0
        for end in range(len(group)):
            while group[end]["timestamp"] - group[start]["timestamp"] > window_sec:
                start += 1
            window = group[start:end + 1]
            ports = [s["dst_port"] for s in window]
            unique = set(ports)
            if len(unique) < min_ports:
                continue
            single = sum(1 for p in unique if ports.count(p) == 1)
            if single / len(unique) < 0.6:
                continue   # port berulang = pemakaian normal, bukan pemindaian
            # Window TERLUAS, bukan yang pertama memenuhi ambang. Berhenti di
            # window pertama membuat scan 40 port dilaporkan sebagai 8 port --
            # angka yang salah, dan justru angka itu yang biasanya ditanyakan.
            if best is None or len(unique) > best["port_count"]:
                best = {
                    "source_ip": source,
                    "ports_scanned": sorted(unique),
                    "port_count": len(unique),
                    "single_touch_ports": single,
                    "window_start_utc": window[0]["time_utc"],
                    "window_end_utc": window[-1]["time_utc"],
                    "duration_sec": round(window[-1]["timestamp"] - window[0]["timestamp"], 1),
                    "confidence": "HIGH",
                    "evidence_query": f"ip.src=={source} && ip.dst=={internal_ip} && "
                                      "tcp.flags.syn==1 && tcp.flags.ack==0",
                }
        if best:
            findings.append(best)

    for hit in findings:
        evidence.track(
            "port_scan", hit["evidence_query"],
            f"{hit['port_count']} port dipindai dari {hit['source_ip']}",
            note=f"{hit['single_touch_ports']} dari {hit['port_count']} port hanya "
                 f"disentuh sekali dalam {hit['duration_sec']} detik sejak "
                 f"{hit['window_start_utc']}. Port: "
                 f"{', '.join(str(p) for p in hit['ports_scanned'][:20])}"
                 + (" ..." if hit["port_count"] > 20 else ""))
    return findings


def detect_port_protocol_mismatch(pcap_path, internal_ip: str,
                                  evidence: EvidenceLog | None = None) -> list[dict]:
    """
    Traffic di port 443 yang tidak pernah melakukan TLS handshake.

    Dicek per tcp.stream: stream yang menuju port 443 tapi tidak punya satu pun
    Client Hello berarti port-nya dipinjam untuk protokol lain -- trik lama C2
    supaya lolos firewall yang hanya melihat nomor port.
    """
    if evidence is None:
        evidence = EvidenceLog()
    port443 = run_tshark_fields(
        pcap_path, f"tcp.dstport==443 && ip.src=={internal_ip} && tcp.len>0",
        ["tcp.stream", "ip.dst"])
    tls_streams = {r["tcp.stream"] for r in run_tshark_fields(
        pcap_path, f"tls.handshake.type==1 && ip.src=={internal_ip}", ["tcp.stream"])}

    seen: dict[str, str] = {}
    for row in port443:
        stream = row["tcp.stream"].split(",")[0]
        if stream and stream not in tls_streams:
            seen.setdefault(stream, row["ip.dst"].split(",")[0])

    findings = []
    for stream, dst in seen.items():
        query = f"tcp.stream=={stream}"
        findings.append({
            "tcp_stream": _int(stream), "destination_ip": dst, "port": 443,
            "issue": "Ada data terkirim ke port 443 tanpa TLS Client Hello",
            "confidence": "MEDIUM",
            "note": "Bisa juga sesi lanjutan/resumption yang handshake-nya di luar "
                    "rentang capture -- verifikasi manual isi stream-nya",
            "evidence_query": query,
        })
        evidence.track("port_protocol_mismatch", query, f"{dst}:443 tanpa TLS handshake",
                       note=findings[-1]["note"])
    return findings


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
