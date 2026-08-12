"""Pisahkan biaya ekspor tshark dari biaya post-processing di file_carver."""
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.services import tools  # noqa: E402
from backend.services.hash_analyzer import analyze_file  # noqa: E402
from backend.services.tools import run  # noqa: E402

pcap = sys.argv[1]
out = Path("storage/carved/_probe")
if out.exists():
    shutil.rmtree(out)
out.mkdir(parents=True)

start = time.perf_counter()
run([tools.resolve("tshark"), "-r", pcap, "--export-objects", f"http,{out}"],
    timeout=900, check=False)
export_time = time.perf_counter() - start

files = [f for f in out.iterdir() if f.is_file()]
big = [f for f in files if f.stat().st_size >= 512]

sample = big[:300]
start = time.perf_counter()
for f in sample:
    analyze_file(f)
per_file = (time.perf_counter() - start) / max(len(sample), 1)

print(f"tshark export   : {export_time:6.1f}s")
print(f"objek ditulis   : {len(files)}")
print(f"objek >=512 B   : {len(big)}")
print(f"analyze_file    : {per_file * len(big):6.1f}s (ekstrapolasi dari {len(sample)} sampel)")
shutil.rmtree(out, ignore_errors=True)
