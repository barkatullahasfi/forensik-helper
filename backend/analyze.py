"""
Pipeline analisis pcap + CLI.

    python -m backend.analyze <file.pcap> [target_ip]

Sengaja bisa dijalankan tanpa web/DB: modul inti harus bisa divalidasi terhadap
pcap yang sudah pernah dianalisis manual sebelum ada satu baris pun frontend.
"""
import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config as settings
from .services import (attack_timeline, beacon_detector, dga_detector,
                       dns_chain_analyzer, file_carver,
                       geoip_enrichment, host_inventory, identity_extractor,
                       investigation_summary, ja3_fingerprint, kerberos_analyzer,
                       location_analyzer, mitre_mapper, narrative_generator,
                       osint_helper, owasp_detector, pcap_parser, protocol_anomaly,
                       smb_analyzer, threat_feed, tool_fingerprint, volume_analyzer)
from .services.timeline_builder import EvidenceLog, build_full_timeline


def analyze_pcap(pcap_path, target_ip: str | None = None, progress=print) -> dict:
    """Jalankan seluruh modul MVP terhadap satu pcap, return hasil terstruktur."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap tidak ditemukan: {pcap_path}")

    evidence = EvidenceLog()

    progress("[1/9] Membaca info capture + protokol yang ada...")
    capture_info = pcap_parser.get_capture_info(pcap_path)
    # Satu pass untuk tahu protokol apa saja yang ada. Menghemat belasan pass
    # lain: tanpa ini analisis Kerberos/TLS/SMB tetap dijalankan pada capture
    # yang tidak memuat protokol tersebut sama sekali.
    protocols = pcap_parser.protocol_summary(pcap_path)
    has = lambda *names: pcap_parser.has_protocol(protocols, *names)  # noqa: E731
    skipped: list[str] = []

    host_ranking = pcap_parser.rank_hosts(pcap_path)
    if not target_ip:
        progress("[2/9] Menebak target IP (host paling aktif)...")
        if not host_ranking:
            raise ValueError("Tidak ada alamat IP sama sekali di pcap ini")
        top = host_ranking[0]
        target_ip = top["ip"]
        runners_up = ", ".join(
            f"{h['ip']} ({h['packets_total']} paket)" for h in host_ranking[1:4])
        evidence.track(
            "target_ip", f"ip.addr (total paket terbanyak, cakupan: {top['ranking_scope']})",
            target_ip,
            note=f"DITEBAK OTOMATIS, bukan fakta. {top['packets_total']} paket "
                 f"({top['packets_sent']} kirim / {top['packets_received']} terima)."
                 + (" Capture ini tidak punya alamat privat sama sekali -- kemungkinan "
                    "diambil di sisi server, jadi 'target' di sini berarti host yang "
                    "PALING RAMAI, bukan tentu korbannya."
                    if not top["is_private"] else "")
                 + (f" Kandidat lain: {runners_up}. Pada capture serangan, host yang "
                    "paling banyak MENGIRIM sering justru penyerang -- pastikan target "
                    "ini memang host yang ingin dianalisis" if runners_up else ""))
    else:
        progress(f"[2/9] Target IP ditentukan manual: {target_ip}")

    progress(f"[3/9] Inventaris host + identitas {target_ip}...")
    inventory = host_inventory.build_inventory(pcap_path, evidence)
    identity = identity_extractor.extract_identity(pcap_path, target_ip, evidence, protocols)
    if identity.get("mac"):
        identity["mac_vendor"] = host_inventory.lookup_oui(identity["mac"])

    progress("[4/9] Mengumpulkan sesi TCP + deteksi beaconing...")
    sessions = beacon_detector.collect_sessions(pcap_path, target_ip)
    beacons = beacon_detector.detect_beaconing(sessions, evidence, target_ip)
    rotation = beacon_detector.detect_domain_rotation(sessions)
    for hit in rotation:
        evidence.track(
            "domain_rotation",
            f"ip.src=={target_ip} && tcp.flags.syn==1 && tcp.flags.ack==0",
            f"{hit['destination_count']} destinasi berbeda dalam {int(hit['window_end'] - hit['window_start'])} detik",
            note=f"Mulai {hit['window_start_utc']}: {', '.join(hit['distinct_destinations'][:8])}")

    progress("[5/9] Analisis DNS chain + skor DGA...")
    # get_dns_queries dipanggil SEKALI lalu hasilnya dioper. Sebelumnya
    # build_dns_chain memanggilnya sendiri dan analyze memanggilnya lagi --
    # dua pass tshark penuh untuk data yang sama persis.
    dns_queries = (dns_chain_analyzer.get_dns_queries(pcap_path, target_ip)
                   if has("dns", "mdns", "nbns") else [])
    dns_chain = dns_chain_analyzer.build_dns_chain(
        pcap_path, target_ip, evidence=evidence, queries=dns_queries)
    gaps = dns_chain_analyzer.calculate_gap_analysis(dns_chain)
    all_domains = [q["domain"] for q in dns_queries]
    # Skor DGA hanya untuk domain non-noise: 'dns.msftncsi.com' dapat skor 2/4
    # karena entropy tinggi dan panjang, padahal itu layanan Microsoft. Domain
    # yang sudah dikenal tidak perlu dinilai keacakan namanya.
    dga_scores = [d for d in dga_detector.detect_dga_pattern(
                      [q["domain"] for q in dns_queries if not q["is_noise"]])
                  if d["dga_suspicion_score"] >= 2]
    for entry in dga_scores[:10]:
        evidence.track("dga_domain", f'dns.qry.name == "{entry["domain"]}"', entry["domain"],
                       note=f"Skor DGA {entry['dga_suspicion_score']}/4 "
                            f"(entropy ternormalisasi {entry['entropy_normalized']}, "
                            f"deret konsonan {entry['max_consonant_streak']}, "
                            f"TLD tidak umum: {entry['uncommon_tld']})")

    progress("[6/9] Cross-check threat feed...")
    checker = threat_feed.ThreatFeedChecker()
    threat_hits = threat_feed.check_iocs(
        checker, all_domains, [s["dst_ip"] for s in sessions], evidence) if checker.loaded else []

    progress("[7/9] Anomali protokol, Kerberos, volume, JA3...")
    anomalies = {
        "nonstandard_ports": protocol_anomaly.detect_nonstandard_c2_ports(
            pcap_path, target_ip, evidence),
        "port_protocol_mismatch": (
            protocol_anomaly.detect_port_protocol_mismatch(pcap_path, target_ip, evidence)
            if has("tls", "ssl") else []),
        "kerberos": (kerberos_analyzer.detect_kerberos_anomalies(pcap_path, target_ip, evidence)
                     if has("kerberos") else {"findings": [], "summary": {}}),
    }
    if not has("kerberos"):
        skipped.append("kerberos (tidak ada paket Kerberos di capture)")
    volume = volume_analyzer.detect_data_exfil_spikes(pcap_path, target_ip, evidence=evidence)
    if has("tls", "ssl"):
        ja3 = ja3_fingerprint.extract_ja3_fingerprints(pcap_path, target_ip, evidence)
        ja3_hits = (ja3_fingerprint.lookup_ja3_reputation(ja3, checker, evidence)
                    if checker.loaded and ja3 and "skipped" not in ja3[0] else [])
    else:
        ja3, ja3_hits = [], []
        skipped.append("JA3/TLS (tidak ada lalu lintas TLS)")

    result_smb = (smb_analyzer.analyze(pcap_path, evidence)
                  if has("smb", "smb2") else {})
    if not has("smb", "smb2"):
        skipped.append("SMB (tidak ada lalu lintas SMB di capture)")
    tools_used = tool_fingerprint.analyze(pcap_path, evidence) if has("http") else []

    progress("[8/9] Deteksi serangan web + carving file...")
    if has("http"):
        progress(f"      memindai {protocols.get('http', 0)} frame HTTP "
                 "untuk pola serangan...")
        owasp = owasp_detector.detect_owasp_patterns(pcap_path, evidence)
        progress(f"      {len(owasp)} pola OWASP cocok")
    else:
        owasp = []
        skipped.append("OWASP (tidak ada lalu lintas HTTP tidak terenkripsi)")
    carved = file_carver.extract_transferred_files(
        pcap_path, threat_checker=checker if checker.loaded else None, evidence=evidence,
        protocols=protocols, progress=progress)

    progress("[9/9] Menyusun timeline, MITRE mapping, dan narasi...")
    result = build_full_timeline(identity, beacons, sessions, evidence, capture_info)
    result["beacons"] = beacons
    result["domain_rotation"] = rotation
    result["dns_chain"] = dns_chain
    result["dns_gaps"] = gaps
    result["dga_scores"] = dga_scores
    result["threat_feed_hits"] = threat_hits
    result["threat_feed_stats"] = checker.stats()
    result["anomalies"] = anomalies
    result["volume"] = volume
    result["ja3"] = {"fingerprints": ja3, "summary": ja3_fingerprint.summarize_ja3(ja3),
                     "known_malicious": ja3_hits}
    result["owasp_findings"] = owasp
    result["owasp_summary"] = owasp_detector.summarize(owasp)
    result["carved_files"] = carved
    result["mitre"] = mitre_mapper.map_from_evidence(evidence.records)

    geoip = geoip_enrichment.enrich_ips([s["dst_ip"] for s in sessions])
    result["geoip"] = {"status": geoip_enrichment.status(), "results": geoip}
    result["locations"] = location_analyzer.build_location_timeline(geoip, [])
    result["location_summary"] = location_analyzer.summarize(result["locations"])
    result["participant_profile"] = osint_helper.build_participant_profile(identity, result)
    result["host_ranking"] = host_ranking
    result["inventory"] = inventory
    result["smb"] = result_smb
    result["tools_used"] = tools_used
    result["exposed_services"] = protocol_anomaly.map_exposed_services(
        sessions, target_ip, evidence)
    result["port_scans"] = protocol_anomaly.detect_port_scan(sessions, target_ip,
                                                             evidence=evidence)
    # Seluruh IP di capture, bukan cuma tujuan dari host target. Korelasi lintas
    # evidence membutuhkan ini: RAM dump bisa berasal dari host lain di capture
    # yang sama, dan mencocokkannya ke all_sessions saja akan selalu nihil.
    # Diambil dari host_ranking + sesi yang sudah dibaca -- memanggil all_ips()
    # berarti satu pass tshark penuh lagi untuk data yang sudah ada.
    result["all_ips"] = sorted(
        {h["ip"] for h in host_ranking}
        | {s["dst_ip"] for s in sessions} | {s["src_ip"] for s in sessions})
    result["protocols"] = protocols
    result["skipped_modules"] = skipped
    result["analysis_id"] = uuid.uuid4().hex[:12]
    result["filename"] = pcap_path.name
    result["status"] = "done"      # record dari CLI dan dari API harus punya
                                   # bentuk yang sama, kalau tidak /api/analysis
                                   # menampilkan baris kosong untuk hasil CLI
    result["analyzed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["tshark_version"] = pcap_parser.tshark_version()
    # Percakapan memakai pass yang sudah di-cache oleh rank_hosts -- tidak ada
    # pembacaan pcap tambahan di sini.
    result["conversations"] = pcap_parser.conversations(pcap_path)
    result["attack_timeline"] = attack_timeline.build(
        result, conversations=result["conversations"])
    result["investigation"] = investigation_summary.summarize(result)
    # Narasi disusun TERAKHIR: ia membaca hasil semua modul di atas.
    result["narrative"] = narrative_generator.generate_narrative(result)
    result["appendix"] = narrative_generator.build_appendix(result)
    return result


def save_result(result: dict) -> Path:
    """
    Hasil disimpan sebagai satu file JSON per analisis.

    ponytail: belum pakai SQLAlchemy/SQLite. Untuk tools personal, hasil analisis
    ditulis sekali lalu dibaca apa adanya -- tidak ada query lintas analisis yang
    membenarkan 20 tabel ORM. Pindah ke DB kalau nanti butuh cari "semua analisis
    yang menyentuh IOC X" tanpa membuka tiap file.
    """
    settings.init_storage()
    path = settings.ANALYSIS_DIR / f"{result['analysis_id']}.json"
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def print_report(result: dict) -> None:
    identity = result["identity"]
    summary = result["session_summary"]
    print("\n" + "=" * 72)
    print(f"  IDENTITAS HOST")
    print("=" * 72)
    print(f"  IP        : {identity['ip']}")
    print(f"  MAC       : {identity['mac'] or '(tidak ditemukan)'}")
    print(f"  Hostname  : {', '.join(identity['hostname']) or '(tidak ditemukan)'}")
    print(f"  Username  : {identity['username'] or '(tidak ditemukan)'}")
    fullname = identity["full_name"] or "(tidak ditemukan -- normal kalau environment tidak query info user)"
    print(f"  Full name : {fullname}")

    print("\n" + "=" * 72)
    print("  SESI KONEKSI")
    print("=" * 72)
    print(f"  {summary['total_sessions']} sesi TCP dengan {summary['unique_destinations']} host "
          f"({summary.get('sessions_outbound', 0)} keluar / "
          f"{summary.get('sessions_inbound', 0)} masuk); "
          f"{summary['sessions_with_payload']} berisi payload HTTP, "
          f"{summary['sessions_idle']} idle/kosong")

    if result.get("investigation"):
        print("\n" + "=" * 72)
        print("  RINGKASAN INVESTIGASI")
        print("=" * 72)
        for item in result["investigation"]:
            print(f"\n  [{item['confidence']:<6}] {item['question']}")
            print(f"      -> {item['answer']}")
            for line in item["detail"]:
                print(f"         · {line}")
            if item.get("evidence_query"):
                print(f"      filter: {item['evidence_query']}")
            if item.get("caveat"):
                print(f"      !! {item['caveat']}")

    attack = result.get("attack_timeline") or {}
    if attack.get("events"):
        print("\n" + "=" * 72)
        print(f"  KRONOLOGI SERANGAN   korban {attack['victim']} <- penyerang {attack['attacker']}")
        print("=" * 72)
        for phase in attack["phases"]:
            phase_events = attack["phases"][phase]
            if not phase_events:
                continue
            print(f"\n  --- {phase} ---")
            for e in phase_events[:10]:
                when = e["time_utc"] or "(waktu tidak diketahui)"
                mark = " [inferensi]" if e["is_inference"] else ""
                print(f"  {when}  [{e['confidence']:<6}]{mark}")
                print(f"      {e['actor']}: {e['action']}")
                if e.get("target"):
                    print(f"      -> {e['target']}")
                if e.get("data"):
                    print(f"      data: {e['data']}")
        movement = attack.get("data_movement") or {}
        if movement.get("verdict"):
            print(f"\n  --- Aliran data ---")
            print(f"  {movement['verdict']}")
            for peer in movement["peers"][:5]:
                tag = "  <- PENYERANG" if peer["is_attacker"] else ""
                print(f"    {peer['peer']:<18} keluar {peer['victim_sent_bytes']:>10,} B"
                      f"   masuk {peer['victim_received_bytes']:>10,} B{tag}")
            print(f"  !! {movement['caveat']}")
        if attack.get("unresolved"):
            print("\n  --- Belum terjawab ---")
            for gap in attack["unresolved"]:
                print(f"  · {gap}")

    print("\n" + "=" * 72)
    print("  TIMELINE UTAMA")
    print("=" * 72)
    for event in result["key_events"]:
        print(f"  {event['time_utc']}  [{event['confidence']:<6}] {event['category']}")
        print(f"    {event['description']}")
        if event.get("evidence_query"):
            print(f"    filter: {event['evidence_query']}")

    beacons = [b for b in result["beacons"] if b["is_suspected_beacon"]]
    print("\n" + "=" * 72)
    print(f"  KANDIDAT BEACON ({len(beacons)} dari {len(result['beacons'])} destinasi dianalisis)")
    print("=" * 72)
    for b in beacons[:15]:
        noise = "  [destinasi umum -- verifikasi manual]" if b["is_known_noise"] else ""
        print(f"  [{b['confidence']:<6}] {b['label']}")
        print(f"            {b['connection_count']} koneksi, interval {b['mean_interval_sec']}s, "
              f"CV {b['coefficient_variation']}{noise}")
    if not beacons:
        print("  (tidak ada destinasi dengan interval cukup teratur)")

    if result["domain_rotation"]:
        print("\n" + "=" * 72)
        print("  ROTASI DOMAIN")
        print("=" * 72)
        for hit in result["domain_rotation"][:5]:
            print(f"  {hit['window_start_utc']}: {hit['destination_count']} destinasi berbeda")
            print(f"    {', '.join(hit['distinct_destinations'][:8])}")

    inv = result.get("inventory") or {}
    extras = [
        ("INVENTARIS HOST", [
            f"{inv.get('layer2_device_count', 0)} perangkat di layer 2 "
            f"({inv.get('host_count', 0)} host, {inv.get('gateway_count', 0)} gateway) | "
            f"{inv.get('ip_count_total', 0)} IP unik: {inv.get('ip_breakdown', {})}"
        ] + [f"  {d['mac']}  {', '.join(d['ip_addresses'][:3])}"
             f"  [{d['role']}] {d['vendor'] or 'vendor tidak dikenal'}"
             + ("  VIRTUAL" if d["is_virtual"] else "")
             for d in inv.get("devices", [])[:8]] if inv else []),
        ("ALAT PENYERANG (dari User-Agent)", [
            f"{t['tool'] or 'tidak dikenal'} ({t['category']}) -- {t['request_count']} request "
            f"dari {', '.join(t['sources'])}\n      {t['user_agent'][:100]}"
            for t in result.get("tools_used", []) if t["is_attack_tool"]]),
        ("SMB", [
            f"share diakses: {', '.join((result.get('smb') or {}).get('shares_accessed', []))}"
        ] + [f"berkas web-executable: {f['basename']} "
             f"({f['access_count']}x, frame {f['first_frame']})"
             for f in (result.get("smb") or {}).get("web_executables", [])]
            if (result.get("smb") or {}).get("shares_accessed") else []),
        ("PORT SCAN", [
            f"{s['source_ip']} memindai {s['port_count']} port dalam {s['duration_sec']}s "
            f"sejak {s['window_start_utc']} ({s['single_touch_ports']} port disentuh sekali)"
            for s in result.get("port_scans", [])]),
        ("LAYANAN TEREKSPOS", [
            f"port {s['port']}/tcp ({s['service']}) -- {s['connection_count']} koneksi "
            f"dari {len(s['distinct_sources'])} sumber, {s['sessions_with_payload']} berpayload"
            for s in result.get("exposed_services", [])[:10]]),
        ("THREAT FEED", [f"[{h.get('confidence', 'HIGH')}] {h['value']} -- {h['source']}"
                         + ("  (layanan hosting publik: yang terdaftar URL spesifik "
                            "di host ini, BUKAN host-nya)" if h.get("shared_hosting") else "")
                         for h in result.get("threat_feed_hits", [])]),
        ("SKOR DGA", [f"{d['domain']} (skor {d['dga_suspicion_score']}/4, "
                      f"entropy {d['entropy_normalized']})"
                      for d in result.get("dga_scores", [])[:10]]),
        ("FILE TER-CARVE", [f"[{f['confidence']}] {f['filename']} ({f['protocol']}, "
                            f"{f['file_size']} B) sha256 {f['exact_hashes']['sha256'][:32]}..."
                            for f in result.get("carved_files", [])[:15]]),
        ("SERANGAN WEB (OWASP)", [f"{k}: {v}" for k, v in
                                  result.get("owasp_summary", {}).get("by_category", {}).items()]),
        ("ANOMALI PORT/PROTOKOL", [f"{a['destination_ip']}:{a['port']} -- {a['reason']}"
                                   for a in result.get("anomalies", {}).get("nonstandard_ports", [])[:10]]),
        ("SPIKE VOLUME", [f"{s['bucket_start_utc']}: {s['total_mb']} MB -- {s['reason']}"
                          for s in result.get("volume", {}).get("spikes", [])[:10]]),
        ("MITRE ATT&CK", [f"{m['technique']} {m['name']} <- {', '.join(m['supporting_findings'])}"
                          for m in result.get("mitre", [])]),
    ]
    for title, lines in extras:
        if lines:
            print("\n" + "=" * 72)
            print(f"  {title}")
            print("=" * 72)
            for line in lines:
                print(f"  {line}")

    if result.get("narrative"):
        print("\n" + "=" * 72)
        print("  NARASI SIAP TEMPEL")
        print("=" * 72)
        for para in result["narrative"].split("\n\n"):
            print(f"  {para}\n")

    print("\n" + "=" * 72)
    print(f"  APPENDIX REPRODUCIBILITY ({len(result['evidence_index'])} temuan)")
    print("=" * 72)
    for record in result["evidence_index"]:
        print(f"  {record['finding_type']}: {record['result']}")
        print(f"    filter: {record['wireshark_filter']}")
        if record["note"]:
            print(f"    catatan: {record['note']}")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Analisis pcap: identitas host, beaconing, timeline, evidence index")
    parser.add_argument("pcap", help="path file .pcap/.pcapng")
    parser.add_argument("target_ip", nargs="?", help="IP host internal (default: tebak otomatis)")
    parser.add_argument("--json", action="store_true", help="cetak JSON mentah, bukan laporan")
    parser.add_argument("--quiet", action="store_true", help="sembunyikan progress")
    args = parser.parse_args(argv)

    progress = (lambda *a, **k: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    try:
        result = analyze_pcap(args.pcap, args.target_ip, progress=progress)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result)
    saved = save_result(result)
    print(f"Hasil lengkap: {saved}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
