"""Ukur waktu tiap tahap pipeline pcap. python tests/profile_pipeline.py <file.pcap>"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import analyze  # noqa: E402

pcap = sys.argv[1]
marks = []


def progress(message):
    marks.append((time.perf_counter(), message))
    print(f"  {message}", file=sys.stderr)


start = time.perf_counter()
result = analyze.analyze_pcap(pcap, sys.argv[2] if len(sys.argv) > 2 else None, progress)
total = time.perf_counter() - start

print("\n--- waktu per tahap ---")
for (t0, label), (t1, _) in zip(marks, marks[1:] + [(time.perf_counter(), "")]):
    print(f"{t1 - t0:7.1f}s  {label}")
print(f"{total:7.1f}s  TOTAL")
print(f"\npaket: {result['capture_info']['packet_count']}, "
      f"sesi: {result['session_summary']['total_sessions']}")
