"""Konfigurasi global. Diimpor di modul lain sebagai `from backend import config as settings`."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Timeout jangan di-hardcode di call site: pcap latihan 50 MB selesai dalam detik,
# pcap 1 GB butuh belasan menit. Kena TimeoutExpired di tengah = seluruh job gagal
# tanpa hasil parsial.
TSHARK_TIMEOUT = int(os.getenv("TSHARK_TIMEOUT", "900"))
VOL_TIMEOUT = int(os.getenv("VOL_TIMEOUT", "1800"))
TSK_TIMEOUT = int(os.getenv("TSK_TIMEOUT", "900"))

# 0 = tools.preflight() hanya melapor tool yang hilang, tidak menginstall apa pun.
AUTO_INSTALL = os.getenv("AUTO_INSTALL", "1") == "1"

# Batas ukuran untuk operasi yang membaca SELURUH berkas.
#
# `ppdeep` adalah implementasi pure-Python: memproses 4,6 GB RAM dump memakan
# waktu berjam-jam dan hasilnya tidak berguna -- tidak ada yang membandingkan
# RAM dump atau disk image berdasarkan kemiripan struktur. Berkas di atas batas
# ini dilewati dengan alasan yang dicatat, bukan digantung tanpa penjelasan.
MAX_FUZZY_HASH_BYTES = int(os.getenv("MAX_FUZZY_HASH_BYTES", str(128 * 1024 * 1024)))

# Scanner signature dan ekstraksi string memuat berkas ke memori sekaligus.
# Tanpa batas, satu disk image multi-GB membuat proses kehabisan RAM.
MAX_INMEMORY_SCAN_BYTES = int(os.getenv("MAX_INMEMORY_SCAN_BYTES", str(512 * 1024 * 1024)))

STORAGE = Path(os.getenv("STORAGE_DIR", ROOT / "storage"))
UPLOAD_DIR = STORAGE / "uploads"
ANALYSIS_DIR = STORAGE / "analyses"
FEED_DIR = STORAGE / "feeds"


def init_storage() -> None:
    for d in (UPLOAD_DIR, ANALYSIS_DIR, FEED_DIR):
        d.mkdir(parents=True, exist_ok=True)
