"""
Bersihkan hasil analisis, upload, dan berkas carving.

    python tests/clean_storage.py [--feeds]

Feed threat intel TIDAK dihapus kecuali diminta -- mengunduhnya ulang butuh
koneksi, dan isinya bukan hasil analisis.

Memakai _force_unlink dari file_carver: nama objek HTTP berasal dari URL, jadi
sebagian berkas hasil carving bisa bernama device khusus Windows ('nul', 'con',
'com1') yang tidak bisa dihapus lewat API biasa.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import config as settings  # noqa: E402
from backend.services.file_carver import _force_unlink  # noqa: E402

targets = [settings.ANALYSIS_DIR, settings.UPLOAD_DIR, settings.STORAGE / "carved"]
if "--feeds" in sys.argv:
    targets.append(settings.FEED_DIR)

for directory in targets:
    if not directory.exists():
        continue
    count = 0
    for path in sorted(directory.rglob("*"), key=lambda p: -len(p.parts)):
        if path.is_file():
            _force_unlink(path)
            count += 1
    shutil.rmtree(directory, ignore_errors=True)
    print(f"{directory.name:<10} {count} berkas dihapus")

settings.init_storage()
sisa = sum(1 for p in settings.STORAGE.rglob("*") if p.is_file())
print(f"\nstorage siap. {sisa} berkas tersisa"
      + (" (feed threat intel)" if sisa else ""))
