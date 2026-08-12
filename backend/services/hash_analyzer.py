"""
Hash exact + fuzzy hash + deteksi tipe file.

Dipakai dua arah: untuk file yang di-carve dari pcap, dan untuk file apa pun yang
diupload langsung.
"""
import hashlib
from pathlib import Path

from .. import config as settings


def calculate_exact_hashes(file_path) -> dict:
    """MD5/SHA1/SHA256 dalam satu kali baca, streaming per 64 KB."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            for h in hashes.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}


def calculate_fuzzy_hash(file_path) -> str | None:
    """
    Fuzzy hash: deteksi file yang MIRIP, bukan identik -- malware yang
    dimodifikasi sedikit atau di-repack.

    Pakai `ppdeep` (pure Python, format hash kompatibel ssdeep), bukan `ssdeep`
    yang butuh libfuzzy-dev + kompilasi C dan praktis tidak bisa dipasang di
    Windows tanpa toolchain.

    Dilewati untuk berkas besar. `ppdeep` memproses byte per byte di Python
    murni: satu RAM dump 4,6 GB menghabiskan berjam-jam CPU, dan hasilnya tidak
    ada gunanya -- tidak ada yang membandingkan RAM dump atau disk image lewat
    kemiripan struktur.
    """
    size = Path(file_path).stat().st_size
    if size > settings.MAX_FUZZY_HASH_BYTES:
        return None
    try:
        import ppdeep
    except ImportError:
        return None
    return ppdeep.hash_from_file(str(file_path))


def compare_fuzzy_hashes(hash1: str, hash2: str) -> int:
    """Skor kemiripan 0-100. 0 = tidak mirip, 100 = identik."""
    import ppdeep
    return ppdeep.compare(hash1, hash2)


def detect_file_type(file_path) -> str:
    """
    Tipe file dari KONTEN, bukan ekstensi -- ekstensi adalah hal pertama yang
    dipalsukan.

    `puremagic` dipilih daripada `python-magic` karena tidak butuh libmagic DLL
    yang tidak tersedia di Windows.
    """
    try:
        import puremagic
        return puremagic.from_file(str(file_path), mime=True)
    except Exception:  # noqa: BLE001 -- tipe tak dikenal itu normal untuk
        return "application/octet-stream"   # evidence, bukan alasan gagal


def analyze_file(file_path, threat_checker=None) -> dict:
    """Entry point: hash lengkap + tipe + ukuran + cross-check threat feed."""
    path = Path(file_path)
    hashes = calculate_exact_hashes(path)   # SEKALI saja: memanggil dua kali
                                            # berarti membaca ulang seluruh file
    size = path.stat().st_size
    fuzzy = calculate_fuzzy_hash(path)
    result = {
        "filename": path.name,
        "file_size": size,
        "file_type": detect_file_type(path),
        "exact_hashes": hashes,
        "fuzzy_hash": fuzzy,
        "fuzzy_hash_skipped": (
            f"berkas {size // 1048576} MB melebihi batas "
            f"{settings.MAX_FUZZY_HASH_BYTES // 1048576} MB -- fuzzy hash tidak "
            "informatif untuk evidence sebesar ini dan sangat lambat"
            if fuzzy is None and size > settings.MAX_FUZZY_HASH_BYTES else None),
        "threat_feed_match": None,
    }
    if threat_checker is not None:
        match = threat_checker.check_file_hash(hashes["sha256"])
        if not match["is_known_malicious"]:
            match = threat_checker.check_file_hash(hashes["md5"])
        result["threat_feed_match"] = match
        result["is_known_malicious"] = match["is_known_malicious"]
    return result


def compare_files(paths: list, threshold: int = 50) -> list[dict]:
    """
    Bandingkan tiap pasang file lewat fuzzy hash.

    Menjawab tipe soal "file A dan B beda hash SHA256, apakah tetap berhubungan?"
    """
    entries = [{"path": Path(p), "fuzzy": calculate_fuzzy_hash(p),
                "sha256": calculate_exact_hashes(p)["sha256"]} for p in paths]
    pairs = []
    for i, a in enumerate(entries):
        for b in entries[i + 1:]:
            identical = a["sha256"] == b["sha256"]
            similarity = 100 if identical else (
                compare_fuzzy_hashes(a["fuzzy"], b["fuzzy"]) if a["fuzzy"] and b["fuzzy"] else 0)
            if similarity >= threshold:
                pairs.append({
                    "file_a": a["path"].name, "file_b": b["path"].name,
                    "similarity": similarity, "identical": identical,
                    "note": "Hash exact sama" if identical else
                            f"Hash exact BEDA tapi kemiripan struktur {similarity}% -- "
                            "kemungkinan varian/modifikasi dari file yang sama",
                })
    return sorted(pairs, key=lambda p: -p["similarity"])
