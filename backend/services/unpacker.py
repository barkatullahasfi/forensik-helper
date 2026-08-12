"""
Membongkar berkas ter-pack dan wadah arsip, lalu menyerahkan isinya untuk
dianalisis ulang.

Alasan modul ini ada: strings dan import table dari berkas TER-PACK tidak
mencerminkan isinya. Menyimpulkan "tidak ada IOC di dalam binary ini" tanpa
membongkarnya lebih dulu adalah kesimpulan yang salah, bukan temuan negatif.

Isi arsip DIKENDALIKAN PENYUSUN BERKAS. Dua serangan klasik ditangani di sini:
zip slip (entry bernama '../../etc/passwd' menulis di luar direktori tujuan) dan
zip bomb (arsip kecil yang mengembang jadi puluhan gigabyte).
"""
import zipfile
from pathlib import Path

from . import tools
from .timeline_builder import EvidenceLog
from .tools import run

# Batas ekspansi. Arsip 42 KB yang mengembang jadi 4,5 PB adalah teknik lama dan
# masih efektif -- tanpa batas ini, membuka satu berkas bukti bisa memenuhi disk.
MAX_TOTAL_EXTRACTED = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_ENTRIES = 5000

ZIP_LIKE = {".apk", ".jar", ".zip", ".xapk", ".aab", ".war", ".ipa", ".docx",
            ".xlsx", ".pptx", ".odt"}


def detect_container(file_path, pe_info: dict | None = None) -> str | None:
    """Jenis wadah/packer, dari header berkas dan hasil parsing PE."""
    path = Path(file_path)
    packer = ((pe_info or {}).get("packer") or {}).get("packer")
    if packer == "UPX":
        return "upx"
    head = path.open("rb").read(4)
    if head[:2] == b"PK":
        return "apk" if path.suffix.lower() in (".apk", ".xapk", ".aab") else "zip"
    if path.suffix.lower() in ZIP_LIKE:
        return "zip"
    if packer:
        return "packed_unsupported"
    return None


def _safe_members(archive: zipfile.ZipFile, destination: Path) -> list:
    """
    Saring entry arsip yang berbahaya SEBELUM apa pun ditulis ke disk.

    Nama entry berasal dari pembuat arsip, jadi bisa berisi '..' atau path
    absolut yang menulis di luar direktori tujuan (zip slip). Rasio kompresi
    ekstrem menandakan zip bomb.
    """
    safe, rejected, total = [], [], 0
    root = destination.resolve()
    for info in archive.infolist()[:MAX_ENTRIES]:
        if info.is_dir():
            continue
        target = (destination / info.filename).resolve()
        if not str(target).startswith(str(root)):
            rejected.append((info.filename, "menulis di luar direktori tujuan (zip slip)"))
            continue
        if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_COMPRESSION_RATIO:
            rejected.append((info.filename,
                             f"rasio kompresi {info.file_size // max(info.compress_size, 1)}x "
                             "-- indikasi zip bomb"))
            continue
        total += info.file_size
        if total > MAX_TOTAL_EXTRACTED:
            rejected.append((info.filename, "total ekstraksi melewati batas"))
            break
        safe.append(info)
    return safe, rejected


def unpack_zip(file_path, output_dir) -> dict:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(file_path) as archive:
            members, rejected = _safe_members(archive, destination)
            for info in members:
                archive.extract(info, destination)
    except zipfile.BadZipFile as e:
        return {"method": "zip", "success": False, "error": str(e), "files": []}
    extracted = [p for p in destination.rglob("*") if p.is_file()]
    return {
        "method": "zip", "success": True, "output_dir": str(destination),
        "files": [str(p) for p in extracted],
        "file_count": len(extracted),
        "rejected": [{"entry": name, "reason": reason} for name, reason in rejected],
    }


def unpack_upx(file_path, output_dir) -> dict:
    """
    `upx -d` menulis ke SALINAN, tidak pernah ke berkas aslinya.

    Bukti tidak boleh diubah. upx membongkar di tempat secara bawaan, jadi
    berkasnya disalin dulu -- kalau tidak, hash evidence berubah dan seluruh
    rantai bukti rusak.
    """
    if not tools.is_available("upx"):
        return {"method": "upx", "success": False, "files": [],
                "error": "upx belum terpasang",
                "hint": "Windows: winget install UPX.UPX | Linux: sudo apt install upx-ucl"}
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    copy = destination / (Path(file_path).stem + "_unpacked" + Path(file_path).suffix)
    copy.write_bytes(Path(file_path).read_bytes())
    try:
        run([tools.resolve("upx"), "-d", "-q", str(copy)], timeout=300)
    except RuntimeError as e:
        copy.unlink(missing_ok=True)
        return {"method": "upx", "success": False, "files": [], "error": str(e)[:300],
                "hint": "Berkas mungkin memakai UPX yang dimodifikasi -- teknik umum "
                        "untuk menggagalkan pembongkaran otomatis. Perlu dibongkar manual "
                        "lewat debugger."}
    return {"method": "upx", "success": True, "output_dir": str(destination),
            "files": [str(copy)], "file_count": 1,
            "original_size": Path(file_path).stat().st_size,
            "unpacked_size": copy.stat().st_size}


def unpack(file_path, output_dir, pe_info: dict | None = None,
           evidence: EvidenceLog | None = None) -> dict:
    """Bongkar berkas kalau ia memang wadah/ter-pack. Return hasil beserta metodenya."""
    if evidence is None:
        evidence = EvidenceLog()
    kind = detect_container(file_path, pe_info)
    if kind is None:
        return {"method": None, "success": False, "files": [],
                "reason": "bukan arsip dan tidak terdeteksi ter-pack"}
    if kind == "packed_unsupported":
        packer = ((pe_info or {}).get("packer") or {}).get("packer")
        return {"method": None, "success": False, "files": [],
                "reason": f"ter-pack dengan {packer}, belum ada pembongkar otomatis",
                "hint": "Bongkar manual, lalu analisis ulang berkas hasilnya"}

    result = unpack_upx(file_path, output_dir) if kind == "upx" else unpack_zip(file_path, output_dir)
    result["container_type"] = kind

    if result["success"]:
        detail = (f"{result.get('original_size')} -> {result.get('unpacked_size')} byte"
                  if kind == "upx" else f"{result['file_count']} berkas diekstrak")
        evidence.track("unpacked", f"{result['method']} {Path(file_path).name}", detail,
                       note="Strings, import table, dan IOC di bawah ini berasal dari "
                            "hasil BONGKARAN, bukan dari berkas asli. Hash evidence "
                            "aslinya tidak berubah.")
    for item in result.get("rejected", []):
        evidence.track("archive_entry_rejected", f"zipinfo {Path(file_path).name}",
                       item["entry"], note=item["reason"])
    return result


def summarize_apk(extracted_files: list[str]) -> dict:
    """
    Ringkasan khas Android dari isi APK yang sudah diekstrak.

    AndroidManifest.xml di dalam APK berbentuk XML biner, tapi nama permission,
    package, dan komponen tetap tersimpan sebagai string yang bisa dibaca --
    cukup untuk mengenali kemampuan aplikasi tanpa parser XML biner penuh.
    """
    import re
    manifest = next((f for f in extracted_files
                     if Path(f).name == "AndroidManifest.xml"), None)
    dex_files = [f for f in extracted_files if Path(f).suffix == ".dex"]
    permissions, package = [], None
    if manifest:
        data = Path(manifest).read_bytes()
        text = data.decode("utf-16-le", "ignore") + " " + data.decode("latin-1", "ignore")
        permissions = sorted(set(re.findall(r"android\.permission\.[A-Z_]{3,}", text)))
        names = re.findall(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})\b", text)
        package = next((n for n in names if not n.startswith("android.")), None)
    return {
        "is_apk": bool(manifest),
        "package_hint": package,
        "permissions": permissions,
        "dangerous_permissions": [p for p in permissions if any(
            k in p for k in ("SMS", "CALL", "CONTACTS", "LOCATION", "RECORD_AUDIO",
                             "CAMERA", "READ_PHONE", "ACCESSIBILITY", "SYSTEM_ALERT",
                             "PACKAGES", "STORAGE"))],
        "dex_count": len(dex_files),
        "note": "Permission dibaca dari string di AndroidManifest biner, bukan dari "
                "parser XML penuh -- daftar ini bisa tidak lengkap. Untuk analisis "
                "menyeluruh pakai apktool atau jadx.",
    }
