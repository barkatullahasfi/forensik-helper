"""
Analisis STATIS berkas .exe/.dll/.bin — strings, IOC, header PE.

Modul ini TIDAK PERNAH menjalankan berkas dalam bentuk apa pun. Tidak ada
sandboxing, tidak ada dynamic analysis: itu butuh environment terisolasi yang di
luar scope tools pribadi ini dan berbahaya kalau salah konfigurasi.
"""
import re
from datetime import datetime, timezone
from pathlib import Path

from .hash_analyzer import analyze_file
from .timeline_builder import EvidenceLog

# Import yang menunjukkan kapabilitas, bukan sekadar daftar fungsi.
CAPABILITY_HINTS = {
    "network": ("wininet", "winhttp", "ws2_32", "urlmon", "internetopen", "socket",
                "httpsendrequest", "urldownloadtofile", "wsastartup"),
    "crypto": ("advapi32", "bcrypt", "crypt32", "cryptencrypt", "cryptacquirecontext"),
    "process_injection": ("virtualallocex", "writeprocessmemory", "createremotethread",
                          "ntunmapviewofsection", "setthreadcontext", "queueuserapc"),
    "persistence": ("regsetvalue", "regcreatekey", "createservice", "schtasks",
                    "startservice"),
    "anti_analysis": ("isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
                      "queryperformancecounter", "gettickcount", "ntqueryinformationprocess"),
    "keylogging": ("setwindowshookex", "getasynckeystate", "getkeyboardstate"),
    "screen_capture": ("bitblt", "getdc", "createcompatiblebitmap"),
    "credential_access": ("credenumerate", "lsaretrieveprivatedata", "samconnect"),
}


def extract_strings(file_path, min_length: int = 6) -> list[str]:
    """
    String printable — ASCII dan UTF-16LE.

    Pass UTF-16 wajib: malware Windows menyimpan mayoritas string-nya sebagai
    wide char, jadi tanpa itu URL C2 sering tidak terlihat sama sekali.

    Ditulis dengan regex, bukan subprocess ke `strings`: binary itu bagian dari
    binutils dan TIDAK ADA di Windows.
    """
    data = Path(file_path).read_bytes()
    ascii_s = [m.decode("ascii") for m in
               re.findall(rb"[\x20-\x7e]{%d,}" % min_length, data)]
    wide_s = [m.decode("utf-16-le", "ignore") for m in
              re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length, data)]
    return ascii_s + wide_s


def find_iocs_in_strings(strings_list: list[str]) -> dict:
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_pattern = r'https?://[^\s"\'<>\\]{4,}'
    domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,12}\b"
    path_pattern = r"[A-Za-z]:\\\\?[\w\\\-. ]{4,80}|\\\\[\w\-.]+\\[\w\\\-. ]{2,60}"
    joined = "\n".join(strings_list)

    ips = {ip for ip in re.findall(ip_pattern, joined) if _plausible_ip(ip)}
    domains = {d.lower() for d in re.findall(domain_pattern, joined, re.IGNORECASE)
               if _plausible_domain(d)}
    return {
        "ips": sorted(ips),
        "urls": sorted(set(re.findall(url_pattern, joined)))[:200],
        "domains": sorted(domains)[:200],
        "file_paths": sorted(set(re.findall(path_pattern, joined)))[:100],
        "registry_keys": sorted({s for s in strings_list
                                 if s.startswith(("HKEY_", "SOFTWARE\\", "SYSTEM\\"))})[:50],
    }


def _plausible_ip(ip: str) -> bool:
    """Buang version string seperti '1.2.3.4' yang sebenarnya nomor versi."""
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts):
        return False
    return not all(int(p) < 20 for p in parts)


def _plausible_domain(domain: str) -> bool:
    """Buang nama fungsi/berkas yang kebetulan berbentuk domain (mis. 'msvcrt.dll')."""
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld not in {"dll", "exe", "sys", "obj", "lib", "pdb", "dat", "bin", "tmp",
                       "ini", "log", "txt", "cpp", "h", "c", "res", "drv", "ocx"}


def parse_pe_header(file_path) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile belum terpasang (pip install pefile)"}
    try:
        pe = pefile.PE(str(file_path), fast_load=False)
    except Exception as e:  # noqa: BLE001 -- bukan PE itu hasil yang sah
        return {"is_pe": False, "reason": str(e)}

    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imports.append({
            "dll": entry.dll.decode(errors="replace"),
            "functions": [i.name.decode(errors="replace") for i in entry.imports if i.name],
        })

    sections = [{"name": s.Name.decode(errors="replace").strip("\x00"),
                 "virtual_size": s.Misc_VirtualSize,
                 "raw_size": s.SizeOfRawData,
                 "entropy": round(s.get_entropy(), 2)} for s in pe.sections]

    timestamp = pe.FILE_HEADER.TimeDateStamp
    compiled = (datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
                if 0 < timestamp < 4102444800 else None)

    # Packer biasanya menyisakan sedikit section dengan entropy tinggi dan
    # raw_size jauh lebih kecil dari virtual_size.
    high_entropy = [s for s in sections if s["entropy"] > 7.0]
    packed = bool(high_entropy) or len(sections) <= 2

    return {
        "is_pe": True,
        "compile_timestamp": compiled,
        "compile_timestamp_raw": timestamp,
        "machine": hex(pe.FILE_HEADER.Machine),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "sections": sections,
        "imports": imports,
        "imported_dll_count": len(imports),
        "is_packed_heuristic": packed,
        "packed_reason": (f"{len(high_entropy)} section entropy > 7.0" if high_entropy
                          else f"hanya {len(sections)} section" if packed else None),
        "capabilities": detect_capabilities(imports),
    }


def detect_capabilities(imports: list[dict]) -> dict:
    """Terjemahkan import table jadi kapabilitas yang bisa ditulis di laporan."""
    haystack = " ".join(
        (entry["dll"] + " " + " ".join(entry["functions"])).lower() for entry in imports)
    return {name: sorted(h for h in hints if h in haystack)
            for name, hints in CAPABILITY_HINTS.items()
            if any(h in haystack for h in hints)}


def analyze_binary(file_path, threat_checker=None,
                   evidence: EvidenceLog | None = None) -> dict:
    if evidence is None:
        evidence = EvidenceLog()
    path = Path(file_path)
    strings_list = extract_strings(path)
    iocs = find_iocs_in_strings(strings_list)
    pe = parse_pe_header(path)
    result = {**analyze_file(path, threat_checker), "iocs": iocs, "pe": pe,
              "string_count": len(strings_list)}

    if result.get("is_known_malicious"):
        evidence.track("binary_known_malicious", f"sha256 {result['exact_hashes']['sha256']}",
                       path.name, note="Cocok dengan hash di ThreatFox")
    for url in iocs["urls"][:10]:
        evidence.track("binary_hardcoded_url", f"strings {path.name} | grep http", url,
                       note="URL tertanam di dalam binary (analisis statis)")
    if pe.get("compile_timestamp"):
        evidence.track("binary_compile_time", f"pefile {path.name} FILE_HEADER.TimeDateStamp",
                       pe["compile_timestamp"],
                       note="Timestamp compile bisa dipalsukan penulis malware -- "
                            "perlakukan sebagai petunjuk, bukan fakta")
    for capability, hits in (pe.get("capabilities") or {}).items():
        evidence.track("binary_capability", f"pefile {path.name} DIRECTORY_ENTRY_IMPORT",
                       capability, note=f"Berdasarkan import: {', '.join(hits[:6])}")
    return result
