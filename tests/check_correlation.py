"""Cek manual korelasi lintas evidence terhadap hasil analisis yang tersimpan."""
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.services import cross_evidence_correlator as correlator  # noqa: E402


def load(name: str) -> dict:
    matches = [json.load(open(f, encoding="utf-8"))
               for f in glob.glob("storage/analyses/*.json")]
    hits = [r for r in matches if r.get("filename") == name]
    if not hits:
        raise SystemExit(f"belum ada hasil analisis untuk {name}")
    return hits[-1]


pcap = load("capture.pcapng")
memory = load("memdump.mem")["memory"]

print(f"pcap   : target {pcap['identity']['ip']}, {len(pcap['all_ips'])} IP di capture")
print(f"memory : {memory['process_count']} proses, {len(memory['connections'])} koneksi")

result = correlator.correlate_all(pcap_result=pcap, memory_result=memory)
print(f"\nkorelasi: {result['correlation_count']}  sumber: {result['sources_used']}\n")

seen = set()
for item in result["correlations"]:
    # `port` WAJIB masuk kunci: satu proses bisa memiliki banyak port (System
    # PID 4 memegang 80 dan 445 sekaligus), dan tanpa port salah satu temuan
    # tertelan dedupe -- justru yang paling penting, port 80.
    key = (item["type"], item.get("ip"), item.get("pid"), item.get("port"))
    if key in seen:
        continue
    seen.add(key)
    print(f"[{item['confidence']}] {item['type']}")
    print(f"   {item['description']}")
    print(f"   filter: {item.get('evidence_query')}")
