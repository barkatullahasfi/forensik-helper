"""
Identifikasi perangkat yang dipakai penyerang dari header HTTP.

User-Agent adalah bukti paling langsung tentang ALAT apa yang dipakai, dan
paling sering terlewat karena tenggelam di antara ribuan header lain. Ia mudah
dipalsukan -- tapi penyerang yang memakai perkakas dengan setelan bawaan
biasanya tidak repot mengubahnya, dan itulah yang terlihat di sini.
"""
import re
from collections import Counter

from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, to_utc

# Pola -> (nama alat, kategori). Dicocokkan pada User-Agent apa adanya.
TOOL_SIGNATURES = [
    (r"nmap scripting engine|\bnmap\b", "Nmap", "pemindai jaringan"),
    (r"sqlmap", "sqlmap", "eksploitasi SQL injection"),
    (r"nikto", "Nikto", "pemindai kerentanan web"),
    (r"dirbuster|gobuster|feroxbuster|\bdirb\b|ffuf", "Pemindai direktori", "enumerasi konten web"),
    (r"wpscan", "WPScan", "pemindai WordPress"),
    (r"acunetix|nessus|qualys|openvas|nuclei", "Pemindai kerentanan", "pemindai otomatis"),
    (r"metasploit|meterpreter", "Metasploit", "framework eksploitasi"),
    (r"burp|zaproxy|owasp zap", "Proxy pengujian web", "intersepsi manual"),
    (r"hydra|medusa|patator", "Alat brute force", "serangan kredensial"),
    (r"masscan|zgrab", "Pemindai massal", "pemindaian internet"),
    (r"havij|netsparker", "Pemindai komersial", "pemindai otomatis"),
    (r"python-requests|python-urllib|go-http-client|libwww-perl|okhttp",
     "Skrip khusus", "otomasi buatan sendiri"),
    (r"^curl/|^wget/", "curl/wget", "pengambilan berkas baris perintah"),
    (r"powershell|windowspowershell", "PowerShell", "otomasi Windows"),
    (r"microsoft-cryptoapi|microsoft bits|windows-update", "Komponen Windows", "lalu lintas sistem"),
]


def classify(user_agent: str) -> dict:
    lowered = (user_agent or "").lower()
    for pattern, name, category in TOOL_SIGNATURES:
        if re.search(pattern, lowered):
            return {"tool": name, "category": category,
                    "is_attack_tool": category not in ("lalu lintas sistem",)}
    return {"tool": None, "category": "peramban atau tidak dikenal", "is_attack_tool": False}


def analyze(pcap_path, evidence: EvidenceLog | None = None) -> list[dict]:
    """User-Agent unik beserta siapa yang memakainya dan kapan pertama kali."""
    if evidence is None:
        evidence = EvidenceLog()
    rows = run_tshark_fields(
        pcap_path, "http.user_agent",
        ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "http.user_agent",
         "http.request.uri"])

    agents: dict[str, dict] = {}
    for row in rows:
        agent = row["http.user_agent"].split(",")[0].strip()
        if not agent:
            continue
        entry = agents.setdefault(agent, {
            "user_agent": agent, "request_count": 0, "sources": Counter(),
            "first_seen": _float(row["frame.time_epoch"]),
            "first_frame": _int(row["frame.number"]),
            "sample_uri": row["http.request.uri"].split(",")[0],
        })
        entry["request_count"] += 1
        entry["sources"][row["ip.src"].split(",")[0]] += 1

    results = []
    for entry in agents.values():
        info = classify(entry["user_agent"])
        record = {
            **entry, **info,
            "sources": [ip for ip, _ in entry["sources"].most_common()],
            "time_utc": to_utc(entry["first_seen"]),
            "evidence_query": f'http.user_agent contains "{entry["user_agent"][:40]}"',
        }
        results.append(record)
        if info["is_attack_tool"]:
            evidence.track(
                "attack_tool_identified", record["evidence_query"],
                f"{info['tool']} ({info['category']})",
                note=f"User-Agent: {entry['user_agent']}. {entry['request_count']} request "
                     f"dari {', '.join(record['sources'])} sejak {record['time_utc']} "
                     f"(frame {entry['first_frame']}). User-Agent mudah dipalsukan -- "
                     "ini menunjukkan perkakas dengan setelan bawaan, bukan bukti mutlak.")
    return sorted(results, key=lambda r: (not r["is_attack_tool"], -r["request_count"]))


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
