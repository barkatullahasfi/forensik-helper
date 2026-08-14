"""
Pipeline analisis berkas non-pcap: gambar, dokumen, audio, executable, disk
image, RAM dump, atau berkas arbitrer.

    python -m backend.analyze_file <berkas> [...]

Semua berkas melewati langkah universal (hash + tipe + metadata) dulu, baru
bercabang sesuai kategorinya.
"""
import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config as settings
from .services import (attack_timeline, binary_analyzer, disk_image_analyzer,
                       hash_analyzer, location_analyzer, log_analyzer,
                       memory_analyzer, metadata_extractor, mitre_mapper,
                       reverse_engineer, steganography_detector, threat_feed,
                       unpacker)
from .services.timeline_builder import EvidenceLog

DISK_IMAGE_EXT = {".e01", ".dd", ".raw", ".img", ".vmdk", ".001"}
MEMORY_EXT = {".mem", ".vmem", ".dmp", ".raw", ".lime", ".core"}
BINARY_EXT = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}
LOG_EXT = {".log", ".w3c", ".iis", ".jsonl", ".ndjson"}


LOG_NAMES = {"syslog", "messages", "secure", "auth", "access", "error", "audit"}


def _is_log(path: Path, mime: str) -> bool:
    """
    Nama berkas dulu, lalu isinya.

    Log yang dirotasi bernama `access.log.3.gz`, jadi mencocokkan suffix saja
    meleset. Log syslog di Linux malah sering tanpa ekstensi sama sekali
    (`/var/log/secure`) -- untuk itu isinya yang harus dibaca.
    """
    name = path.name.lower()
    if any(name.endswith(ext) or f"{ext}." in name for ext in LOG_EXT):
        return True
    if path.stem.lower() in LOG_NAMES or name in LOG_NAMES:
        return True
    if not (mime.startswith("text/") or mime in ("application/octet-stream", "")):
        return False
    try:
        with log_analyzer._open(path) as handle:
            sample = [next(handle, "") for _ in range(50)]
    except (OSError, UnicodeDecodeError):
        return False
    return log_analyzer.detect_format(sample) != "unknown"


def categorize(path: Path, mime: str) -> str:
    """
    Kategori dari MIME (konten) DAN ekstensi.

    Ekstensi saja tidak cukup -- itu hal pertama yang dipalsukan. MIME saja juga
    tidak cukup: disk image dan RAM dump sama-sama terdeteksi sebagai
    octet-stream, hanya ekstensi yang membedakan.
    """
    ext = path.suffix.lower()
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/") or ext in {".wav", ".mp3", ".flac", ".au"}:
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if ext in BINARY_EXT or mime in ("application/x-dosexec", "application/x-msdownload"):
        return "binary"
    if ext in (".apk", ".xapk", ".aab", ".jar", ".zip", ".war", ".ipa"):
        return "archive"
    if ext in DISK_IMAGE_EXT:
        return "disk_image"
    if ext in MEMORY_EXT:
        return "memory_dump"
    # Diperiksa sebelum "document": log server adalah text/plain, dan
    # memperlakukannya sebagai dokumen berarti ia cuma dipindai steganografi.
    if _is_log(path, mime):
        return "log"
    if mime.startswith("text/") or ext in {".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".odt"}:
        return "document"
    return "generic"


def _unpack_and_reanalyze(path, pe_info, checker, evidence, progress) -> dict:
    """
    Bongkar berkas, lalu jalankan analisis binary ULANG pada hasilnya.

    Ini yang menutup celah paling merepotkan: IOC di dalam berkas ter-pack tidak
    terlihat sampai berkasnya dibongkar. Menganalisis berkas asli lalu berhenti
    di situ menghasilkan "tidak ditemukan domain apa pun" -- kesimpulan yang
    salah, bukan temuan negatif.
    """
    out_dir = settings.STORAGE / "unpacked" / path.stem
    result = unpacker.unpack(path, out_dir, pe_info, evidence)
    if not result.get("success"):
        return {"unpacked": result}

    progress(f"      dibongkar ({result['method']}) — menganalisis ulang isinya...")
    inner = []
    for extracted in result["files"][:40]:
        target = Path(extracted)
        if target.stat().st_size < 64:
            continue
        info = hash_analyzer.analyze_file(target, checker)
        # Analisis binary penuh hanya untuk berkas yang memang kode; untuk isi
        # arsip lain, hash dan IOC dari strings sudah cukup.
        if info["file_type"].endswith(("executable", "x-dosexec")) or \
                target.suffix.lower() in (".exe", ".dll", ".dex", ".so"):
            info["iocs"] = binary_analyzer.find_iocs_in_strings(
                binary_analyzer.extract_strings(target))
        else:
            info["iocs"] = binary_analyzer.find_iocs_in_strings(
                binary_analyzer.extract_strings(target, min_length=8))
        inner.append(info)

    merged = {"ips": set(), "urls": set(), "domains": set()}
    for info in inner:
        for key in merged:
            merged[key].update(info.get("iocs", {}).get(key, []))
    for url in sorted(merged["urls"])[:15]:
        evidence.track("unpacked_url", f"strings <hasil bongkaran {path.name}>", url,
                       note="URL ditemukan SETELAH pembongkaran — tidak terlihat di "
                            "berkas aslinya yang masih ter-pack")
    for domain in sorted(merged["domains"])[:25]:
        evidence.track("unpacked_domain", f"strings <hasil bongkaran {path.name}>", domain,
                       note="Domain ditemukan setelah pembongkaran. Cocokkan dengan "
                            "lalu lintas DNS di pcap untuk memastikan ia benar-benar "
                            "dihubungi, bukan sekadar tertanam di kode")

    extra = {"unpacked": result,
             "unpacked_files": inner,
             "unpacked_iocs": {k: sorted(v) for k, v in merged.items()}}
    if result.get("container_type") == "apk":
        extra["apk"] = unpacker.summarize_apk(result["files"])
    return extra


def analyze(path, progress=print) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"berkas tidak ditemukan: {path}")

    # Tangkapan lalu lintas diteruskan ke pipeline jaringan, bukan diperlakukan
    # sebagai berkas biasa. Tanpa ini, `analyze_file capture.pcapng` menjalankan
    # pemindaian steganografi pada pcap -- boros dan hasilnya tidak menjawab
    # apa pun tentang lalu lintasnya.
    if settings.is_pcap(path):
        progress(f"{path.name} adalah tangkapan lalu lintas — dialihkan ke analisis pcap")
        from .analyze import analyze_pcap
        return analyze_pcap(path, progress=progress)

    evidence = EvidenceLog()
    checker = threat_feed.ThreatFeedChecker()
    checker = checker if checker.loaded else None

    progress("[1/3] Hash + deteksi tipe berkas...")
    base = hash_analyzer.analyze_file(path, checker)
    category = categorize(path, base["file_type"])
    evidence.track("file_hash", f"sha256sum {path.name}", base["exact_hashes"]["sha256"],
                   note=f"Tipe terdeteksi dari konten: {base['file_type']} "
                        f"({base['file_size']} byte). Fuzzy hash: {base['fuzzy_hash']}")
    if base.get("is_known_malicious"):
        evidence.track("threat_feed_match", f"sha256 {base['exact_hashes']['sha256']}",
                       path.name, note="Hash cocok dengan ThreatFox (abuse.ch)")

    progress("[2/3] Ekstraksi metadata...")
    # exiftool tidak punya apa pun untuk dilaporkan dari disk image atau RAM dump,
    # tapi tetap akan memindai seluruh berkas multi-GB untuk mencari struktur
    # yang memang tidak ada di sana.
    if category in ("disk_image", "memory_dump"):
        metadata = {"skipped": f"metadata tidak relevan untuk {category}"}
    else:
        metadata = metadata_extractor.analyze_metadata(path, evidence)

    progress(f"[3/3] Analisis khusus kategori '{category}'...")
    specific: dict = {}
    if category in ("image", "audio", "video", "document", "generic"):
        specific["steganography"] = steganography_detector.full_scan(
            path, base["file_type"], evidence=evidence)
    if category == "binary":
        specific["binary"] = binary_analyzer.analyze_binary(path, checker, evidence)
        progress("      analisis reverse engineering statis...")
        specific["reverse"] = reverse_engineer.analyze(
            path, settings.STORAGE / "unpacked" / f"{path.stem}_re", evidence)
    if category in ("binary", "archive", "generic"):
        specific.update(_unpack_and_reanalyze(
            path, specific.get("binary", {}).get("pe"), checker, evidence, progress))
    if category == "disk_image":
        specific["disk"] = disk_image_analyzer.analyze_disk_image(path, evidence)
    if category == "memory_dump":
        specific["memory"] = memory_analyzer.full_memory_triage(path, checker, evidence)
    if category == "log":
        specific["log"] = log_analyzer.analyze(path, evidence)

    memory_result = specific.get("memory") or {}
    mitre = mitre_mapper.map_from_evidence(
        evidence.records, extra=memory_result.get("lolbin_execution"))
    timeline = attack_timeline.build_from_memory(memory_result, path.name)
    # Log punya kronologinya sendiri, dalam bentuk yang sama. RAM dump dan log
    # tidak pernah datang dari berkas yang sama, jadi cukup dipakai yang ada isinya.
    if not timeline.get("events") and specific.get("log", {}).get("timeline"):
        timeline = specific["log"]["timeline"]

    gps = (metadata or {}).get("gps")
    locations = location_analyzer.build_location_timeline(
        [], [{**gps, "filename": path.name}] if gps else [])

    return {
        "analysis_id": uuid.uuid4().hex[:12],
        "status": "done",
        "filename": path.name,
        "file_path": str(path.resolve()),   # dibutuhkan perbandingan fuzzy hash
                                            # antar berkas; basename saja tidak
                                            # bisa dibuka ulang dari cwd lain
        "file_category": category,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **base,
        "metadata": metadata,
        **specific,
        "locations": locations,
        "location_summary": location_analyzer.summarize(locations),
        "mitre": mitre,
        "attack_timeline": timeline,
        "evidence_index": evidence.records,
    }


def print_report(result: dict) -> None:
    print("\n" + "=" * 72)
    print(f"  {result['filename']}  ({result['file_category']})")
    print("=" * 72)
    print(f"  Tipe    : {result['file_type']}   {result['file_size']} byte")
    for name, value in result["exact_hashes"].items():
        print(f"  {name.upper():<8}: {value}")
    print(f"  ssdeep  : {result.get('fuzzy_hash')}")
    match = result.get("threat_feed_match") or {}
    print(f"  Threat  : {'COCOK di ' + str(match.get('source')) if match.get('is_known_malicious') else 'tidak terdaftar di feed (bukan berarti aman)'}")

    metadata = result.get("metadata") or {}
    if metadata.get("gps"):
        gps = metadata["gps"]
        print(f"\n  GPS     : {gps['latitude']}, {gps['longitude']}   {gps['maps_url']}")
    authorship = metadata.get("authorship") or {}
    shown = {k: v for k, v in authorship.items() if v}
    if shown:
        print("\n  METADATA")
        for key, value in shown.items():
            print(f"    {key:<18}: {value}")
    for flag in metadata.get("anomaly_flags") or []:
        print(f"    [!] {flag}")

    stego = result.get("steganography") or {}
    if (stego.get("embedded_signatures") or stego.get("trailing_data")
            or stego.get("readable_text")):
        print("\n  STEGANOGRAFI")
        for item in stego.get("embedded_signatures", [])[:10]:
            print(f"    {item['type']} @ {item['offset_hex']}")
        t = stego.get("trailing_data")
        if t and t["marker_missing"]:
            print(f"    [!] penanda akhir {t['marker']} TIDAK ADA — berkas terpotong "
                  "atau sengaja diubah")
            print(f"        ekor berkas: {t['preview_ascii'][:70]}")
        elif t:
            print(f"    {t['trailing_bytes']} byte setelah {t['marker']}: "
                  f"{t['preview_ascii'][:60]}")
        # Dicetak sebelum interesting_strings: inilah yang menemukan pesan yang
        # tidak memuat kata kunci apa pun.
        for item in stego.get("readable_text", [])[:10]:
            print(f"    teks @ {item['offset_hex']}: {item['text'][:110]}")
        for s in stego.get("interesting_strings", [])[:10]:
            print(f"    string: {s[:100]}")

    binary = result.get("binary") or {}
    if binary.get("pe", {}).get("is_pe"):
        pe = binary["pe"]
        print("\n  PE HEADER")
        print(f"    compile   : {pe['compile_timestamp']}")
        packer = pe.get("packer") or {}
        print(f"    packed    : {pe['is_packed_heuristic']} ({pe.get('packed_reason') or '-'})")
        if packer.get("packer"):
            print(f"    packer    : {packer['packer']} [{packer['confidence']}] "
                  f"section {packer['matched_sections']}"
                  + ("  + penanda cocok" if packer["marker_found"] else ""))
            if packer.get("hint"):
                print(f"                {packer['hint']}")
            print("                Strings & import table di bawah ini berasal dari "
                  "berkas TER-PACK —")
            print("                bongkar dulu sebelum menyimpulkan tidak ada IOC.")
        for capability, hits in (pe.get("capabilities") or {}).items():
            print(f"    kapabilitas: {capability} <- {', '.join(hits[:5])}")
        for url in binary["iocs"]["urls"][:10]:
            print(f"    URL       : {url[:100]}")

    memory = result.get("memory") or {}
    if memory.get("available"):
        print("\n" + "=" * 72)
        print("  RAM DUMP")
        print("=" * 72)
        info = memory.get("system_info") or {}
        if info.get("kernel_base"):
            print(f"    kernel base : {info['kernel_base']}   DTB {info.get('dtb')}")
            print(f"    build       : {info.get('build')}  "
                  f"{'64-bit' if info.get('is_64bit') else '32-bit'}, "
                  f"{info.get('processors')} prosesor")
            if info.get("system_time"):
                print(f"    waktu dump  : {info['system_time']}")
        users = memory.get("users") or {}
        print(f"    {memory['process_count']} proses, {len(memory['connections'])} koneksi, "
              f"{len(set(users.values()))} akun pengguna: "
              f"{', '.join(sorted(set(users.values()))[:6]) or '-'}")

        # Rantai induk proses yang ditandai. "PPID 4120" tidak menjelaskan apa
        # pun sendirian; yang menjelaskan alur serangan adalah rantainya.
        flagged = {i["pid"] for i in memory.get("lolbin_execution", [])}
        flagged |= {i["pid"] for i in memory.get("process_hollowing", [])}
        flagged |= {i["pid"] for i in memory.get("persistence", [])}
        branch = [t for t in memory.get("process_tree", []) if t["pid"] in flagged]
        if branch:
            print("\n    POHON PROSES YANG DITANDAI")
            for node in branch:
                print(f"      {node['name']} (PID {node['pid']})  user={node['user'] or '?'}")
                print(f"        induk    : {node['ancestry']}")
                if not node["parent_exists"]:
                    print(f"        !! induk PPID {node['ppid']} TIDAK ADA di dump — "
                          "proses induk sudah keluar sebelum dump diambil")
                if node.get("create_time"):
                    print(f"        dibuat   : {node['create_time']}")
                if node.get("args"):
                    for line in _wrap(str(node["args"]), 58):
                        print(f"        cmdline  : {line}")
            print()
        for item in memory.get("lolbin_execution", []):
            print(f"    [{item['confidence']:<7}] LOLBin {item['lolbin']} "
                  f"({item['invocation']}) -> {', '.join(item['targets'] or item['unc_paths'])}")
            print(f"             MITRE {item['mitre_technique']} ({item['mitre_name']})")
            print(f"             proses {item['process']} PID {item['pid']} · "
                  f"induk {item.get('parent_name') or '(tidak ada di dump)'} "
                  f"PPID {item.get('ppid')} · user {item.get('user') or '?'}")
            print(f"             {item['args'][:150]}")
        for item in memory.get("remote_shares", []):
            print(f"    [HIGH]   share jauh: {item['unc_path']}")
            print(f"             host {item['host']} · share {item['share']}")
        for item in memory.get("persistence", []):
            print(f"    [HIGH]   persistence: {item['binary'] or item['process']} "
                  f"(PID {item['pid']}) via {item['mechanism']}")
            print(f"             {item['path']}")
        for item in memory.get("process_hollowing", []):
            print(f"    [HIGH]   hollowing: {item['process_name']} -> "
                  f"{item['commandline_binary']} (PID {item['pid']})")
            print(f"             {item['args'][:110]}")
        for item in memory.get("suspicious_command_lines", []):
            print(f"    [{item['confidence']:<7}] {item['process']} (PID {item['pid']}): "
                  f"{'; '.join(item['reasons'])}")
            print(f"             {item['args'][:110]}")
            if item.get("known_legitimate"):
                print(f"             lokasi sah untuk proses ini: {item['known_legitimate']}")
        for entry in memory.get("code_injection_by_process", []):
            tag = "catatan" if entry["known_false_positive"] else "MEDIUM"
            print(f"    [{tag:<7}] malfind: {entry['process']} (PID {entry['pid']}), "
                  f"{entry['region_count']} region")
            if entry["known_false_positive"]:
                print(f"             {entry['known_false_positive']}")
        for conn in memory.get("notable_connections", [])[:12]:
            print(f"    [{conn['confidence']:<7}] koneksi: {conn['process']} "
                  f"(PID {conn['pid']}) {conn['local']} -> {conn['foreign']} {conn['state'] or ''}")
            for reason in conn["reasons"]:
                print(f"             {reason}")

    disk = result.get("disk") or {}
    if disk.get("available"):
        print("\n  DISK IMAGE")
        print(f"    {disk['total_files']} berkas, {disk['deleted_count']} terhapus, "
              f"offset {disk['offset_used']}")
        for file in disk.get("deleted_files", [])[:15]:
            print(f"    [terhapus] inode {file['inode']:<8} {file['file_path']} "
                  f"({file['size_bytes']} B)")

    runtime = (result.get("binary") or {}).get("runtime") or {}
    if runtime.get("runtime"):
        print(f"    runtime   : {runtime['runtime']}  (penanda: {', '.join(runtime['markers'][:3])})")
        if runtime.get("hint"):
            print(f"                {runtime['hint']}")

    re_result = result.get("reverse") or {}
    if re_result:
        print("\n  REVERSE ENGINEERING (statis)")
        if re_result.get("imphash"):
            print(f"    imphash   : {re_result['imphash']}")
        overlay = re_result.get("overlay") or {}
        if overlay.get("has_overlay"):
            print(f"    overlay   : {overlay['size']} byte @ offset {overlay['offset']} "
                  f"({round(overlay['ratio'] * 100)}% berkas), entropy {overlay['entropy']}"
                  + (f" — {overlay['detected_type']}" if overlay.get("detected_type") else ""))
            print(f"                {overlay['note'][:120]}")
        for item in re_result.get("resources", [])[:8]:
            print(f"    resource  : {item['type']}/{item['name']} {item['size']} B "
                  f"entropy {item['entropy']} — {item['note']}")
        for item in re_result.get("base64_strings", [])[:8]:
            print(f"    base64 @{item['offset']}: {', '.join(item['matches'][:4])}")
        for item in re_result.get("xor_candidates", [])[:3]:
            print(f"    XOR {item['key_hex']} ({item['match_count']} cocok): "
                  f"{', '.join(item['matches'][:4])}")
        entry = re_result.get("entry_point") or {}
        if entry.get("available"):
            print(f"    entry {entry['entry_rva']} ({entry['architecture']}):")
            for line in entry["instructions"][:12]:
                print(f"      {line}")
        elif entry.get("hint"):
            print(f"    entry     : {entry['hint']}")

    unpacked = result.get("unpacked") or {}
    if unpacked.get("success"):
        print(f"\n  HASIL BONGKARAN ({unpacked['method']})")
        if unpacked["method"] == "upx":
            print(f"    {unpacked['original_size']} -> {unpacked['unpacked_size']} byte")
        else:
            print(f"    {unpacked['file_count']} berkas diekstrak ke {unpacked['output_dir']}")
        for item in unpacked.get("rejected", []):
            print(f"    [ditolak] {item['entry']}: {item['reason']}")
        iocs = result.get("unpacked_iocs") or {}
        for label in ("urls", "domains", "ips"):
            for value in (iocs.get(label) or [])[:12]:
                print(f"    {label[:-1]:<7}: {value[:110]}")
        apk = result.get("apk") or {}
        if apk.get("is_apk"):
            print(f"    package : {apk.get('package_hint')}   {apk['dex_count']} berkas dex")
            for perm in apk["dangerous_permissions"][:12]:
                print(f"    izin    : {perm}")
    elif unpacked.get("reason"):
        print(f"\n  BONGKARAN: {unpacked['reason']}")
        if unpacked.get("hint"):
            print(f"    {unpacked['hint']}")

    _print_log(result.get("log") or {})
    _print_attack_timeline(result.get("attack_timeline") or {})
    _print_mitre(result.get("mitre") or [])

    print("\n" + "=" * 72)
    print(f"  APPENDIX REPRODUKSIBILITAS ({len(result['evidence_index'])} temuan)")
    print("=" * 72)
    for i, record in enumerate(result["evidence_index"], 1):
        print(f"\n  {i}. {record['finding_type']} — {record['result']}")
        print(f"     perintah: {record['wireshark_filter']}")
        if record["note"]:
            for line in _wrap(record["note"], 66):
                print(f"     catatan : {line}" if line == _wrap(record["note"], 66)[0]
                      else f"               {line}")
    print()


def _wrap(text: str, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width) or [""]


def _print_log(log: dict) -> None:
    if not log.get("available"):
        return
    s = log["summary"]
    print("\n" + "=" * 72)
    print(f"  LOG SERVER — format {s['format']}")
    print("=" * 72)
    print(f"    {s['lines_parsed']} dari {s['lines_total']} baris terbaca "
          f"({s['parse_rate']:.1%}), {s['unique_sources']} sumber")
    print(f"    rentang     : {s['first_event']} s/d {s['last_event']}")
    # Statistik web hanya untuk log yang memang memuat request. Di auth.log
    # semuanya nol, dan nol terbaca seolah "tidak ada error" -- padahal artinya
    # pertanyaannya tidak berlaku untuk berkas ini.
    if s["web_entries"]:
        print(f"    request web : {s['web_entries']}, {s['unique_paths']} path unik")
        print(f"    status      : {s['by_status']}")
        print(f"    error rate  : {s['error_rate']:.1%}   {s['bytes_served']} byte dilayani")
    # Angka ini disebut lebih dulu daripada temuannya. Parser yang gagal atas
    # mayoritas baris menghasilkan "0 temuan" yang terlihat persis sama dengan
    # log bersih, dan pembaca harus tahu itu SEBELUM membaca kesimpulan.
    if s["parse_rate"] < 0.5:
        print(f"    [!] {s['lines_unparsed']} baris TIDAK terbaca — temuan di bawah "
              "tidak meliputi seluruh berkas")
    if s["truncated"]:
        print(f"    [!] berkas dipotong di {s['lines_total']} baris")
    if s["assumed_year"]:
        print(f"    [!] syslog tanpa tahun — diasumsikan {s['assumed_year']} dari mtime berkas")

    for item in log.get("brute_force", []):
        print(f"\n    [{item['confidence']:<6}] BRUTE FORCE dari {item['src_ip']}")
        print(f"             {item['failures']} kegagalan, {item['successes']} berhasil, "
              f"selama {item['duration_sec']:.0f} detik"
              + (f" ({item['attempts_per_min']}/menit)" if item["attempts_per_min"] else ""))
        print(f"             sasaran : {', '.join(item['targeted_users'][:8]) or '?'}")
        print(f"             layanan : {', '.join(item['services'])}")
        print(f"             mulai   : {item['first_attempt']} s/d {item['last_attempt']}")
        if item["compromised"]:
            print(f"             !! LOGIN BERHASIL {item['success_at']} sebagai "
                  f"{', '.join(item['compromised_accounts']) or '(user tidak tercatat)'}")
            print("                Periksa apa yang dilakukan akun itu SETELAH waktu ini.")

    for item in log.get("privilege_use", []):
        print(f"\n    [{item['confidence']:<6}] SUDO oleh {item['user']} "
              f"({item['time_utc']})")
        print(f"             {item['command'][:150]}")
        for reason in item["reasons"]:
            print(f"             -> {reason}")
        if item["after_breach"]:
            print("             !! dijalankan SETELAH login paksa berhasil")
        if item["by_compromised_account"]:
            print("             !! oleh akun yang kredensialnya jebol")

    for item in log.get("webshells", []):
        print(f"\n    [{item['confidence']:<6}] WEBSHELL? {item['uri']}")
        print(f"             {item['reason']}")
        print(f"             {item['requests']} request dari {', '.join(item['sources'][:4])}, "
              f"metode {', '.join(item['methods'])}, status {item['statuses']}")
        print(f"             {item['bytes_total']} byte terkirim · {item['first_seen']} "
              f"s/d {item['last_seen']}")
        if not item["server_answered"]:
            print("             Server tidak pernah menjawab 2xx — kemungkinan besar "
                  "hanya percobaan.")

    for item in log.get("encoded_parameters", [])[:20]:
        print(f"\n    [{item['confidence']:<6}] PARAMETER TER-ENCODE baris {item['line_number']} "
              f"dari {item['src_ip']} (status {item['status']})")
        print(f"             {item['uri'][:110]}")
        print(f"             {item['parameter']}= {item['encoded'][:80]}")
        print(f"             terdekode -> {item['decoded'][:110]}")
        if item["iocs"]:
            print(f"             memuat   : {', '.join(item['iocs'][:6])}")
        if item["common_token_name"]:
            print("             nama parameternya lazim dipakai token sesi — bisa saja sah")

    for item in log.get("scanners", [])[:10]:
        label = item["tool"] or ("Enumerasi" if item["is_enumeration"] else "?")
        print(f"\n    [MEDIUM] {label} dari {item['src_ip']} ({item['tool_category']})")
        print(f"             {item['requests']} request, {item['unique_paths']} path unik, "
              f"{item['not_found']} × 404 ({item['not_found_ratio']:.0%})")
        if item["requests_per_min"]:
            print(f"             {item['requests_per_min']} request/menit selama "
                  f"{item['duration_sec']:.0f} detik")
        for tool in item.get("tools", []):
            print(f"             {tool['requests']:>5} request  {tool['tool']} "
                  f"({tool['category']})")
            print(f"                   UA: {tool['user_agent'][:90]}")

    attacks = log.get("attack_summary") or {}
    if attacks.get("total"):
        print(f"\n    SERANGAN WEB: {attacks['total']} request dari "
              f"{', '.join(attacks['attackers'][:6])}")
        for category, count in sorted(attacks["by_category"].items(), key=lambda x: -x[1]):
            print(f"      {count:>4} × {category}")
        print(f"      outcome: {attacks['by_outcome']}")
        for item in log.get("web_attacks", [])[:15]:
            print(f"      [{item['confidence']:<6}] baris {item['line_number']:<7} "
                  f"{item['src_ip']} {item['http_method']} -> {item['response_status']} "
                  f"({item['outcome']})")
            print(f"               {item['request_uri'][:110]}")

    # Sepuluh response terbesar SELALU ada di log mana pun; yang layak dicetak
    # adalah yang porsinya menonjol. Sisanya cuma mengisi layar.
    big = [i for i in log.get("large_transfers", []) if i["share_of_total"] >= 0.05]
    for item in big[:5]:
        print(f"\n    [catatan] {item['bytes']} byte ({item['share_of_total']:.0%} dari total) "
              f"ke {item['src_ip']}")
        print(f"              {item['uri'][:110]}")

    top = log.get("top_sources") or []
    if top:
        print("\n    SUMBER TERATAS")
        for row in top[:10]:
            print(f"      {row['src_ip']:<40} {row['requests']:>7} request "
                  f"{row['errors']:>6} error  {row['bytes']:>12} byte")


def _print_attack_timeline(timeline: dict) -> None:
    events = timeline.get("events") or []
    if not events:
        return
    print("\n" + "=" * 72)
    print("  KRONOLOGI SERANGAN")
    print("=" * 72)
    if timeline.get("accounts_involved"):
        print(f"  Akun terlibat: {', '.join(timeline['accounts_involved'])}")

    for phase, phase_events in timeline["phases"].items():
        if not phase_events:
            continue
        print(f"\n  --- {phase} ({len(phase_events)}) ---")
        for e in phase_events:
            when = e["time_utc"] or "(waktu tidak tercatat)"
            mark = "  [inferensi]" if e["is_inference"] else ""
            print(f"\n  {when}  [{e['confidence']}]{mark}")
            print(f"     {e['actor']}: {e['action']}")
            # Panah hanya di baris pertama: mengulangnya di baris lanjutan
            # membuat rantai induk 'A <- B <- C' terbaca seolah ada panah baru.
            if e.get("target"):
                for i, line in enumerate(_wrap(str(e["target"]), 62)):
                    print(f"       {'->' if i == 0 else '  '} {line}")
            if e.get("data"):
                for line in _wrap(str(e["data"]), 62):
                    print(f"          {line}")
            if e.get("evidence_query"):
                print(f"       perintah: {e['evidence_query']}")

    if timeline.get("unresolved"):
        print("\n  --- Belum terjawab dari evidence ini ---")
        for gap in timeline["unresolved"]:
            for i, line in enumerate(_wrap(gap, 66)):
                print(f"  {'·' if i == 0 else ' '} {line}")


def _print_mitre(mitre: list) -> None:
    if not mitre:
        return
    print("\n" + "=" * 72)
    print(f"  MITRE ATT&CK ({len(mitre)} teknik)")
    print("=" * 72)
    for item in mitre:
        print(f"  {item['technique']:<12} {item['name']}")
        for finding in item["supporting_findings"][:3]:
            print(f"               <- {finding}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Analisis berkas non-pcap")
    parser.add_argument("files", nargs="+", help="berkas yang dianalisis")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    progress = (lambda *a: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    settings.init_storage()
    results = []
    for target in args.files:
        try:
            result = analyze(target, progress=progress)
        except (FileNotFoundError, RuntimeError) as e:
            print(f"error pada {target}: {e}", file=sys.stderr)
            continue
        results.append(result)
        path = settings.ANALYSIS_DIR / f"{result['analysis_id']}.json"
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8")
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        elif "all_sessions" in result:
            # Hasil pcap punya bentuk berbeda; dicetak oleh pelapornya sendiri.
            from .analyze import print_report as print_pcap_report
            print_pcap_report(result)
        else:
            print_report(result)
        print(f"Hasil lengkap: {path}", file=sys.stderr)

    # Perbandingan fuzzy hash hanya berlaku untuk berkas; hasil pcap tidak punya
    # file_path tunggal untuk dibandingkan.
    comparable = [r["file_path"] for r in results if r.get("file_path")]
    if len(comparable) > 1:
        pairs = hash_analyzer.compare_files(comparable)
        if pairs:
            print("\n  KEMIRIPAN ANTAR BERKAS")
            for pair in pairs:
                print(f"    {pair['file_a']} <-> {pair['file_b']}: {pair['similarity']}% "
                      f"-- {pair['note']}")
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
