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
from .services import (binary_analyzer, disk_image_analyzer, hash_analyzer,
                       location_analyzer, memory_analyzer, metadata_extractor,
                       steganography_detector, threat_feed)
from .services.timeline_builder import EvidenceLog

DISK_IMAGE_EXT = {".e01", ".dd", ".raw", ".img", ".vmdk", ".001"}
MEMORY_EXT = {".mem", ".vmem", ".dmp", ".raw", ".lime", ".core"}
BINARY_EXT = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}


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
    if ext in DISK_IMAGE_EXT:
        return "disk_image"
    if ext in MEMORY_EXT:
        return "memory_dump"
    if mime.startswith("text/") or ext in {".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".odt"}:
        return "document"
    return "generic"


def analyze(path, progress=print) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"berkas tidak ditemukan: {path}")

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
    if category == "disk_image":
        specific["disk"] = disk_image_analyzer.analyze_disk_image(path, evidence)
    if category == "memory_dump":
        specific["memory"] = memory_analyzer.full_memory_triage(path, checker, evidence)

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
    if stego.get("embedded_signatures") or stego.get("trailing_data"):
        print("\n  STEGANOGRAFI")
        for item in stego.get("embedded_signatures", [])[:10]:
            print(f"    {item['type']} @ {item['offset_hex']}")
        if stego.get("trailing_data"):
            t = stego["trailing_data"]
            print(f"    {t['trailing_bytes']} byte setelah {t['marker']}: {t['preview_ascii'][:60]}")
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
        print("\n  RAM DUMP")
        info = memory.get("system_info") or {}
        if info.get("kernel_base"):
            print(f"    kernel base : {info['kernel_base']}   DTB {info.get('dtb')}")
            print(f"    build       : {info.get('build')}  "
                  f"{'64-bit' if info.get('is_64bit') else '32-bit'}, "
                  f"{info.get('processors')} prosesor")
        print(f"    {memory['process_count']} proses, {len(memory['connections'])} koneksi "
              f"({len(memory.get('external_connections', []))} ke IP eksternal)")
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

    print("\n" + "=" * 72)
    print(f"  APPENDIX ({len(result['evidence_index'])} temuan)")
    print("=" * 72)
    for record in result["evidence_index"]:
        print(f"  {record['finding_type']}: {record['result']}")
        print(f"    perintah: {record['wireshark_filter']}")
        if record["note"]:
            print(f"    catatan : {record['note']}")
    print()


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
        else:
            print_report(result)
        print(f"Hasil lengkap: {path}", file=sys.stderr)

    if len(results) > 1:
        pairs = hash_analyzer.compare_files([r["file_path"] for r in results])
        if pairs:
            print("\n  KEMIRIPAN ANTAR BERKAS")
            for pair in pairs:
                print(f"    {pair['file_a']} <-> {pair['file_b']}: {pair['similarity']}% "
                      f"-- {pair['note']}")
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
