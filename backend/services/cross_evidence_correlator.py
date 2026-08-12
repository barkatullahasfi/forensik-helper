"""
Korelasi temuan lintas sumber evidence: pcap + disk image + RAM dump + berkas.

Ini yang menjawab pertanyaan besar khas soal 'evidence pack': bukan "apa temuan
di tiap berkas", tapi "bagaimana semuanya tersambung jadi satu kronologi".
"""
from .timeline_builder import sort_key, to_utc


def correlate_network_and_memory(pcap_result: dict, memory_result: dict) -> list[dict]:
    """
    IP yang muncul di pcap DAN sebagai koneksi proses di RAM dump.

    Ini korelasi paling kuat yang bisa dibuat: menghubungkan traffic ke PROSES
    yang menghasilkannya. Tanpa RAM dump, pcap hanya bisa bilang "host ini
    menghubungi X", tidak pernah "program Y yang melakukannya".
    """
    # `all_ips` mencakup seluruh capture. `all_sessions` hanya lalu lintas KELUAR
    # dari satu host target, jadi memakainya sendirian membuat korelasi selalu
    # nihil setiap kali RAM dump berasal dari host lain di capture yang sama --
    # yang justru kasus paling umum di evidence pack (dump diambil dari korban,
    # target pcap tertebak ke penyerang).
    network_ips = set(pcap_result.get("all_ips") or [])
    network_ips |= {s["dst_ip"] for s in pcap_result.get("all_sessions", [])}
    network_ips |= {h["value"] for h in pcap_result.get("threat_feed_hits", [])}

    correlations = []
    seen_hosts = set()
    for conn in memory_result.get("connections", []):
        remote = str(conn.get("ForeignAddr") or "")
        local = str(conn.get("LocalAddr") or "")

        # Korelasi terkuat: alamat LOKAL dump ada di capture. Itu memastikan RAM
        # dump dan pcap berasal dari mesin yang sama -- fondasi semua kesimpulan
        # lintas evidence berikutnya.
        if local and local in network_ips and local not in seen_hosts:
            seen_hosts.add(local)
            correlations.append({
                "type": "dump_host_identified",
                "confidence": "HIGH",
                "ip": local,
                "description": f"RAM dump berasal dari host {local}, yang juga muncul "
                               f"di pcap -- kedua evidence berasal dari mesin yang sama",
                "evidence_query": f"ip.addr == {local}   |   vol -f <dump> windows.netscan",
                "why_it_matters": "Menetapkan bahwa pcap dan RAM dump memang satu kasus, "
                                  "bukan dua sistem berbeda",
            })

        if remote and remote in network_ips:
            correlations.append({
                "type": "network_process_match",
                "confidence": "HIGH",
                "ip": remote,
                "process_name": conn.get("Owner"),
                "pid": conn.get("PID"),
                "state": conn.get("State"),
                "port": conn.get("ForeignPort"),
                "description": f"IP {remote} muncul di pcap DAN sebagai koneksi proses "
                               f"{conn.get('Owner')} (PID {conn.get('PID')}) di RAM dump"
                               + (f" pada port {conn.get('ForeignPort')}"
                                  if conn.get("ForeignPort") else ""),
                "evidence_query": f"ip.addr == {remote}   |   "
                                  f"vol -f <dump> windows.netscan",
                "why_it_matters": "Menghubungkan lalu lintas jaringan ke proses yang "
                                  "menghasilkannya -- pcap saja tidak bisa menunjukkan ini",
            })

    # Proses yang terindikasi hollowing/injeksi jadi jauh lebih berarti ketika
    # host-nya terbukti sama dengan yang ada di pcap.
    if seen_hosts:
        for item in memory_result.get("process_hollowing", []):
            correlations.append({
                "type": "hollowed_process_on_captured_host",
                "confidence": "HIGH",
                "process_name": item["process_name"],
                "pid": item["pid"],
                "description": f"Proses {item['process_name']} (PID {item['pid']}) "
                               f"menjalankan {item['commandline_binary']} di host "
                               f"{sorted(seen_hosts)[0]} yang lalu lintasnya terekam di pcap",
                "evidence_query": f"vol -f <dump> windows.cmdline --pid {item['pid']}",
                "why_it_matters": "Menempatkan proses yang dimanipulasi pada mesin yang "
                                  "sama dengan lalu lintas yang dianalisis",
            })
    return correlations


def correlate_service_to_process(pcap_result: dict, memory_result: dict) -> list[dict]:
    """
    Port yang diserang di pcap -> PROSES yang mendengarkannya di RAM dump.

    Pcap hanya bisa bilang "port 445 dihubungi 1000 kali". Yang dicari analis
    adalah "layanan apa yang ada di balik port itu" -- dan itu hanya terjawab
    kalau ada RAM dump. Kombinasi keduanya mengubah nomor port jadi nama
    aplikasi, dan itulah yang bisa ditulis di laporan.
    """
    listeners: dict[int, dict] = {}
    for conn in memory_result.get("connections", []):
        port = conn.get("LocalPort")
        if port and conn.get("Owner"):
            listeners.setdefault(int(port), conn)

    correlations = []
    for service in pcap_result.get("exposed_services", []):
        conn = listeners.get(service["port"])
        if not conn:
            continue
        correlations.append({
            "type": "service_process_match",
            "confidence": "HIGH",
            "port": service["port"],
            "service": service["service"],
            "process_name": conn.get("Owner"),
            "pid": conn.get("PID"),
            "description": f"Port {service['port']}/tcp ({service['service']}) menerima "
                           f"{service['connection_count']} koneksi masuk di pcap, dan di RAM "
                           f"dump port itu dimiliki proses {conn.get('Owner')} "
                           f"(PID {conn.get('PID')})",
            "evidence_query": f"tcp.dstport=={service['port']}   |   "
                              f"vol -f <dump> windows.netscan",
            "why_it_matters": "Mengubah nomor port jadi nama aplikasi -- pcap sendirian "
                              "tidak bisa menyebut layanan apa yang sebenarnya diserang",
        })
    return correlations


def correlate_memory_and_disk(memory_result: dict, disk_result: dict,
                              window_sec: int = 300) -> list[dict]:
    """
    Proses di RAM yang berkas executable-nya ada di disk, dengan stempel waktu
    berdekatan.

    Menjawab "KAPAN malware sebenarnya masuk ke sistem" — waktu proses berjalan
    saja tidak cukup, yang dicari adalah kapan berkasnya pertama kali ada.
    """
    by_name: dict[str, list[dict]] = {}
    for file in disk_result.get("deleted_files", []) + [
            f for group in disk_result.get("artifacts", {}).values() for f in group]:
        by_name.setdefault(file["file_path"].split("/")[-1].lower(), []).append(file)

    correlations = []
    for process in memory_result.get("processes", []):
        name = str(process.get("ImageFileName") or "").lower()
        if not name:
            continue
        for file in by_name.get(name, []):
            created = file.get("crtime") or file.get("mtime")
            correlations.append({
                "type": "memory_disk_match",
                "confidence": "MEDIUM",
                "process_name": process.get("ImageFileName"),
                "pid": process.get("PID"),
                "disk_path": file["file_path"],
                "file_created_utc": to_utc(created) if created else None,
                "file_is_deleted": file["is_deleted"],
                "description": f"Proses {process.get('ImageFileName')} "
                               f"(PID {process.get('PID')}) cocok dengan berkas "
                               f"{file['file_path']} di disk"
                               + (" yang SUDAH DIHAPUS" if file["is_deleted"] else ""),
                "caveat": "Kecocokan berdasarkan NAMA berkas saja. Nama bisa "
                          "ditiru -- konfirmasi dengan hash sebelum disimpulkan",
            })
    return correlations


def correlate_hashes(*evidence_results: dict) -> list[dict]:
    """
    Hash yang sama muncul di lebih dari satu sumber evidence.

    Berbeda dari korelasi nama berkas: hash identik adalah bukti, bukan dugaan.
    """
    by_hash: dict[str, list[dict]] = {}
    for result in evidence_results:
        source = result.get("evidence_source", "unknown")
        for file in result.get("carved_files", []) + result.get("analyzed_files", []):
            sha = (file.get("exact_hashes") or {}).get("sha256")
            if sha:
                by_hash.setdefault(sha, []).append(
                    {"source": source, "filename": file.get("filename")})

    return [{"type": "hash_match_across_sources", "confidence": "HIGH", "sha256": sha,
             "appearances": items,
             "description": f"Berkas dengan SHA256 {sha[:16]}... muncul di "
                            f"{len(items)} sumber evidence berbeda: "
                            + ", ".join(f"{i['source']} ({i['filename']})" for i in items),
             "why_it_matters": "Hash identik = berkas yang sama persis, bukan "
                               "kebetulan nama sama"}
            for sha, items in by_hash.items() if len(items) > 1]


def build_master_timeline(*sources: tuple[str, list[dict]]) -> list[dict]:
    """
    Semua event dari semua sumber jadi satu kronologi tunggal.

    Dipakai `sort_key` bersama, BUKAN sort langsung by x["timestamp"]: tiap
    sumber evidence memakai format waktu berbeda (pcap float epoch, disk int
    epoch, metadata string exiftool). Sort naif melempar TypeError begitu dua
    format bertemu -- justru di modul yang paling penting ini.
    """
    events = []
    for source_name, source_events in sources:
        for event in source_events or []:
            events.append({**event, "evidence_source": source_name})
    return sorted(events, key=sort_key)


def correlate_all(pcap_result: dict | None = None, memory_result: dict | None = None,
                  disk_result: dict | None = None, file_results: list[dict] | None = None) -> dict:
    """Entry point untuk skenario evidence pack lengkap."""
    pcap_result = pcap_result or {}
    memory_result = memory_result or {}
    disk_result = disk_result or {}

    correlations = []
    if pcap_result and memory_result:
        correlations += correlate_network_and_memory(pcap_result, memory_result)
        correlations += correlate_service_to_process(pcap_result, memory_result)
    if memory_result and disk_result:
        correlations += correlate_memory_and_disk(memory_result, disk_result)
    correlations += correlate_hashes(
        {**pcap_result, "evidence_source": "pcap"},
        {"analyzed_files": file_results or [], "evidence_source": "berkas terpisah"})

    timeline = build_master_timeline(
        ("pcap", pcap_result.get("key_events")),
        ("disk_image", disk_result.get("mac_timeline_preview")),
        ("memory_dump", [{"timestamp": None, "description": c["description"]}
                         for c in correlations if c["type"] == "network_process_match"]),
    )

    return {
        "correlations": correlations,
        "correlation_count": len(correlations),
        "master_timeline": timeline,
        "sources_used": [name for name, data in
                         (("pcap", pcap_result), ("memory_dump", memory_result),
                          ("disk_image", disk_result), ("files", file_results)) if data],
        "note": "Nilai tertinggi di soal evidence pack biasanya diberikan untuk "
                "KORELASI yang tepat, bukan daftar temuan per berkas.",
    }
