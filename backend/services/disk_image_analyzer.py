"""
Wrapper The Sleuth Kit — parsing disk image tanpa me-mount-nya.

Image tetap read-only; tidak ada tulisan apa pun ke evidence. Format didukung:
raw/dd, E01 (dengan ewf-tools), VMDK.
"""
import re
from datetime import datetime, timezone
from pathlib import Path

from .. import config as settings
from . import tools
from .timeline_builder import EvidenceLog
from .tools import run

# Artefak Windows yang hampir selalu dicari lebih dulu.
INTERESTING_PATHS = {
    "registry": ("/Windows/System32/config/SAM", "/Windows/System32/config/SYSTEM",
                 "/Windows/System32/config/SOFTWARE", "/Windows/System32/config/SECURITY",
                 "NTUSER.DAT", "UsrClass.dat"),
    "execution": ("/Windows/Prefetch/", "Amcache.hve", "/Windows/appcompat/"),
    "logs": ("/Windows/System32/winevt/Logs/",),
    "browser": ("History", "places.sqlite", "cookies.sqlite", "Web Data", "Login Data"),
    "startup": ("/Start Menu/Programs/Startup/", "/Windows/System32/Tasks/"),
}


def available() -> bool:
    return all(tools.is_available(t) for t in ("mmls", "fls", "icat"))


def get_partition_layout(image_path) -> list[dict]:
    """mmls dijalankan PERTAMA: offset partisi dibutuhkan semua perintah lain."""
    if not available():
        return [{"error": "Sleuth Kit belum terpasang (apt install sleuthkit / "
                          "choco install sleuthkit)"}]
    out = run([tools.resolve("mmls"), str(image_path)], timeout=settings.TSK_TIMEOUT,
              check=False)
    partitions = []
    for line in out.splitlines():
        match = re.match(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if match:
            partitions.append({
                "slot": match.group(2), "start_sector": int(match.group(3)),
                "end_sector": int(match.group(4)), "length_sectors": int(match.group(5)),
                "description": match.group(6).strip(),
                "is_filesystem": "Unallocated" not in match.group(6)
                                 and "Meta" not in match.group(6),
            })
    if not partitions:
        # Image tanpa partition table (mis. hasil dd satu partisi) tetap bisa
        # diproses dengan offset 0 -- ini kasus umum untuk image latihan.
        partitions.append({"slot": "-", "start_sector": 0, "description":
                           "Tidak ada partition table; diperlakukan sebagai satu "
                           "filesystem pada offset 0", "is_filesystem": True})
    return partitions


def list_files_recursive(image_path, offset: int = 0,
                         deleted_only: bool = False) -> list[dict]:
    """
    fls -r -m: seluruh berkas termasuk YANG SUDAH DIHAPUS (selama entry
    MFT/inode-nya masih ada). Format bodyfile siap dipakai timeline.
    """
    if not available():
        return []
    out = run([tools.resolve("fls"), "-r", "-m", "/", "-o", str(offset), str(image_path)],
              timeout=settings.TSK_TIMEOUT, check=False)
    files = []
    for line in out.splitlines():
        parts = line.split("|")
        # Format bodyfile TSK punya TEPAT 11 field:
        #   MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
        #    0    1     2     3   4   5    6     7      8      9      10
        # Menuntut 12 field membuat SETIAP baris dilewati dan modul mengembalikan
        # daftar kosong tanpa error apa pun.
        if len(parts) < 11:
            continue
        name, mode = parts[1], parts[3]
        # 'v/v' menandai entry virtual bikinan TSK ($MBR, $FAT1, $OrphanFiles),
        # bukan berkas sungguhan di filesystem. Perbandingan WAJIB case-insensitive:
        # TSK memakai 'V/V' huruf besar untuk direktori virtual seperti
        # $OrphanFiles, sehingga filter case-sensitive melewatkannya.
        if mode.lower().startswith("v/"):
            continue
        files.append({
            "file_path": name.replace("(deleted)", "").replace("(realloc)", "").strip(),
            "inode": parts[2],
            "mode": mode,
            "size_bytes": _int(parts[6]),
            "atime": _epoch(parts[7]), "mtime": _epoch(parts[8]),
            "ctime": _epoch(parts[9]), "crtime": _epoch(parts[10]),
            "is_deleted": "(deleted)" in name,
            "is_reallocated": "(realloc)" in name,   # entry dipakai ulang: isi
                                                     # aslinya kemungkinan tertimpa
        })
    return [f for f in files if f["is_deleted"]] if deleted_only else files


def extract_file_by_inode(image_path, inode: str, output_path, offset: int = 0) -> Path:
    """icat: ekstrak isi berkas berdasarkan inode -- termasuk berkas terhapus."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    run([tools.resolve("icat"), "-o", str(offset), str(image_path), inode],
        timeout=settings.TSK_TIMEOUT, stdout_to=output)
    return output


def build_mac_timeline(image_path, offset: int = 0, limit: int | None = None) -> list[dict]:
    """
    Timeline MAC: satu event per stempel waktu, bukan satu per berkas.

    Satu berkas punya 4 stempel (M/A/C/B) yang bisa berjauhan. Menggabungkannya
    jadi satu baris menyembunyikan justru yang dicari: "apa yang terjadi pada
    rentang waktu X".
    """
    events = []
    for file in list_files_recursive(image_path, offset):
        for field, label in (("mtime", "Modified"), ("atime", "Accessed"),
                             ("ctime", "Changed"), ("crtime", "Created")):
            if file[field]:
                events.append({
                    "timestamp": file[field],
                    "time_utc": datetime.fromtimestamp(
                        file[field], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "action": label, "file_path": file["file_path"],
                    "inode": file["inode"], "size_bytes": file["size_bytes"],
                    "is_deleted": file["is_deleted"],
                })
    events.sort(key=lambda e: e["timestamp"])
    return events[:limit] if limit else events


def find_interesting_artifacts(image_path, offset: int = 0,
                               evidence: EvidenceLog | None = None) -> dict:
    """Kelompokkan berkas menurut kategori artefak forensik yang umum dicari."""
    if evidence is None:
        evidence = EvidenceLog()
    files = list_files_recursive(image_path, offset)
    grouped: dict[str, list[dict]] = {k: [] for k in INTERESTING_PATHS}
    for file in files:
        lowered = file["file_path"].lower()
        for category, patterns in INTERESTING_PATHS.items():
            if any(p.lower() in lowered for p in patterns):
                grouped[category].append(file)

    deleted = [f for f in files if f["is_deleted"]]
    if deleted:
        evidence.track("deleted_files", f"fls -r -d -o {offset} <image>",
                       f"{len(deleted)} berkas terhapus masih punya entry metadata",
                       note="Isinya bisa direcover dengan icat selama blok datanya "
                            "belum ditimpa")
    for category, items in grouped.items():
        if items:
            evidence.track(f"disk_artifact_{category}", f"fls -r -o {offset} <image>",
                           f"{len(items)} berkas", note=f"Contoh: {items[0]['file_path']}")

    return {"total_files": len(files), "deleted_files": deleted[:200],
            "deleted_count": len(deleted),
            "artifacts": {k: v[:100] for k, v in grouped.items() if v}}


def analyze_disk_image(image_path, evidence: EvidenceLog | None = None) -> dict:
    if evidence is None:
        evidence = EvidenceLog()
    if not available():
        return {"error": "Sleuth Kit belum terpasang", "available": False}
    partitions = get_partition_layout(image_path)
    filesystems = [p for p in partitions if p.get("is_filesystem")]
    offset = filesystems[0]["start_sector"] if filesystems else 0
    artifacts = find_interesting_artifacts(image_path, offset, evidence)
    return {
        "available": True, "partitions": partitions, "offset_used": offset,
        **artifacts,
        "mac_timeline_preview": build_mac_timeline(image_path, offset, limit=500),
    }


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _epoch(value):
    try:
        result = int(value)
        return result if result > 0 else None
    except (TypeError, ValueError):
        return None
