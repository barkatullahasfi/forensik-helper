"""
Wrapper Volatility 3 untuk RAM dump.

Beda dengan disk image (data persisten), RAM dump menangkap STATE sistem tepat
saat di-dump: proses berjalan, koneksi aktif, command line, bahkan kode yang
tidak pernah menyentuh disk.
"""
import json
import re

from .. import config as settings
from . import tools
from .timeline_builder import EvidenceLog
from .tools import run

# Pola command line yang layak diperiksa. Menandai, bukan membuktikan.
SUSPICIOUS_CMDLINE = [
    (r"-e(nc|ncodedcommand)\b", "PowerShell encoded command"),
    (r"[A-Za-z0-9+/]{80,}={0,2}", "blob base64 panjang di command line"),
    (r"\b(iex|invoke-expression|downloadstring|downloadfile)\b", "download & execute PowerShell"),
    (r"-w\s+hidden|-windowstyle\s+hidden", "jendela disembunyikan"),
    (r"\b(certutil|bitsadmin|mshta|regsvr32|rundll32)\b.*\b(http|urlcache|javascript)",
     "living-off-the-land binary dipakai mengunduh"),
    (r"\bvssadmin\b.*\bdelete\b|\bwbadmin\b.*\bdelete\b", "penghapusan shadow copy (ransomware)"),
    (r"\\temp\\", "dijalankan dari direktori temporer"),
    # Lokasi persistence. Folder Startup adalah tempat paling umum malware
    # menaruh dirinya, dan memeriksa \temp\ saja MELEWATKANNYA -- terbukti pada
    # dump uji, di mana satu-satunya proses berbahaya berjalan dari Startup.
    (r"\\start menu\\programs\\startup\\", "dijalankan dari folder Startup (persistence)"),
    (r"\\appdata\\roaming\\.*\.exe", "executable di AppData\\Roaming"),
    (r"\\programdata\\.*\.exe", "executable di ProgramData"),
    (r"\\users\\public\\.*\.exe", "executable di folder Public"),
]

# Proses yang secara sah punya region memory RWX dan hampir selalu muncul di
# malfind. Tidak dibuang dari hasil -- ditandai supaya tidak dilaporkan sebagai
# temuan utama padahal itu perilaku normal.
COMMON_MALFIND_FALSE_POSITIVES = {
    "MsMpEng.exe": "Windows Defender -- engine pemindainya memang memakai memori RWX",
    "csrss.exe": "subsistem Windows, umum muncul",
    "svchost.exe": "sangat umum; hanya berarti kalau disertai indikator lain",
    "explorer.exe": "shell Windows, umum muncul",
}


def available() -> bool:
    return tools.is_available("vol")


def run_plugin(dump_path, plugin: str, extra_args: list[str] | None = None) -> list[dict]:
    """
    Volatility 3 mendeteksi profil OS otomatis (tidak seperti Volatility 2).

    Entrypoint yang dipasang `pip install volatility3` bernama **`vol`**, bukan
    `vol3` -- memakai nama salah membuat seluruh modul ini FileNotFoundError.
    """
    if not available():
        return [{"error": "Volatility 3 belum terpasang (pip install volatility3)"}]
    cmd = [tools.resolve("vol"), "-q", "-f", str(dump_path), "-r", "json", plugin]
    if extra_args:
        cmd += extra_args
    out = run(cmd, timeout=settings.VOL_TIMEOUT, check=False)
    try:
        return json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return [{"error": "output volatility bukan JSON", "raw": out[:500]}]


def get_system_info(dump_path) -> dict:
    """
    windows.info — profil OS, alamat basis kernel, DTB, jumlah prosesor.

    Alamat basis kernel adalah titik acuan untuk seluruh analisis memory dan
    sering diminta secara eksplisit; ia keluar dari plugin ini, bukan dari
    daftar proses.
    """
    rows = run_plugin(dump_path, "windows.info")
    info = {}
    for row in rows:
        key, value = row.get("Variable"), row.get("Value")
        if key:
            info[key] = value
    return {
        "raw": info,
        "kernel_base": info.get("Kernel Base"),
        "dtb": info.get("DTB"),
        "os_version": info.get("NtMajorVersion") and
                      f"{info.get('NtMajorVersion')}.{info.get('NtMinorVersion')}",
        "build": info.get("Major/Minor"),
        "is_64bit": str(info.get("Is64Bit", "")).lower() == "true",
        "processors": info.get("KeNumberProcessors"),
        "system_time": info.get("SystemTime"),
    }


def get_process_list(dump_path) -> list[dict]:
    return run_plugin(dump_path, "windows.pslist.PsList")


def get_network_connections(dump_path) -> list[dict]:
    """
    windows.netscan — KUNCI korelasi dengan pcap.

    IP C2 yang sama muncul di pcap DAN sebagai koneksi proses tertentu di RAM
    adalah bukti terkuat soal proses mana yang bertanggung jawab atas traffic itu.
    """
    return run_plugin(dump_path, "windows.netscan.NetScan")


def get_command_lines(dump_path) -> list[dict]:
    return run_plugin(dump_path, "windows.cmdline.CmdLine")


def detect_code_injection(dump_path) -> list[dict]:
    """windows.malfind — region memory executable+writable yang tidak cocok berkas di disk."""
    return run_plugin(dump_path, "windows.malfind.Malfind")


# Proses sistem yang memang berjalan dari lokasi yang biasanya mencurigakan.
# Windows Defender sungguh-sungguh tinggal di ProgramData.
LEGITIMATE_UNUSUAL_PATHS = {
    "MsMpEng.exe": r"C:\ProgramData\Microsoft\Windows Defender",
    "MpCopyAccelerator.exe": r"C:\ProgramData\Microsoft\Windows Defender",
    "NisSrv.exe": r"C:\ProgramData\Microsoft\Windows Defender",
    "MicrosoftEdgeUpdate.exe": r"C:\Program Files (x86)\Microsoft\EdgeUpdate",
}


def flag_suspicious_cmdlines(cmdlines: list[dict]) -> list[dict]:
    flagged = []
    for entry in cmdlines:
        args = str(entry.get("Args") or "")
        process = str(entry.get("Process") or "")
        hits = [label for pattern, label in SUSPICIOUS_CMDLINE
                if re.search(pattern, args, re.IGNORECASE)]
        if not hits:
            continue
        # Ditandai, bukan dibuang: proses sistem yang memang tinggal di lokasi
        # tidak lazim tetap dilaporkan supaya terlihat sudah diperiksa, tapi
        # tidak menutupi temuan sungguhan.
        expected = LEGITIMATE_UNUSUAL_PATHS.get(process)
        benign = bool(expected and expected.lower() in args.lower())
        flagged.append({"pid": entry.get("PID"), "process": process,
                        "args": args[:400], "reasons": hits,
                        "confidence": "LOW" if benign else "MEDIUM",
                        "known_legitimate": expected if benign else None})
    return sorted(flagged, key=lambda f: f["confidence"] == "LOW")


def _executable_from_cmdline(args: str) -> str | None:
    """
    Nama berkas executable dari sebuah command line Windows.

    Memotong di spasi pertama SALAH: path Windows penuh spasi, dan justru
    lokasi yang paling sering dipakai malware mengandung spasi --
    'C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\
    Startup\\update.exe' terpotong jadi '...\\Start', yang bukan .exe sehingga
    baris itu dilewati diam-diam. Kalau di-quote, isi quote itulah path-nya.
    """
    import ntpath
    args = args.strip()
    if args.startswith('"'):
        end = args.find('"', 1)
        path = args[1:end] if end > 0 else args[1:]
    else:
        # Tanpa quote, ambil potongan terpanjang yang masih berakhiran .exe.
        lowered = args.lower()
        index = lowered.find(".exe")
        path = args[:index + 4] if index != -1 else args.split(" ")[0]
    name = ntpath.basename(path.strip())
    return name if name.lower().endswith(".exe") else None


def find_name_path_mismatch(cmdlines: list[dict]) -> list[dict]:
    """
    Nama proses berbeda dari nama executable di command line-nya.

    Ini indikator process hollowing yang kuat dan TIDAK tertangkap pemeriksaan
    pola apa pun: penyerang menjalankan binary sah (mis. RegSvcs.exe) lalu
    menimpa isinya, sehingga Windows tetap melaporkan nama proses aslinya
    sementara command line-nya menunjuk berkas yang sama sekali lain.

    Terbukti pada dump uji: RegSvcs.exe dengan command line
    '...\\Start Menu\\Programs\\Startup\\update.exe'.
    """
    findings = []
    for entry in cmdlines:
        process = str(entry.get("Process") or "")
        args = str(entry.get("Args") or "")
        if not process or not args:
            continue
        binary = _executable_from_cmdline(args)
        if not binary:
            continue
        # Nama proses dipotong 15 karakter oleh Windows, jadi bandingkan prefiks.
        stem, binary_stem = process.lower().removesuffix(".exe"), binary.lower().removesuffix(".exe")
        if not (binary_stem.startswith(stem[:14]) or stem.startswith(binary_stem[:14])):
            findings.append({
                "pid": entry.get("PID"), "process_name": process,
                "commandline_binary": binary, "args": args[:300],
                "confidence": "HIGH",
                "note": f"Proses melaporkan diri sebagai '{process}' tapi command "
                        f"line-nya menjalankan '{binary}' -- indikasi process "
                        f"hollowing / masquerading",
            })
    return findings


def find_orphan_processes(processes: list[dict]) -> list[dict]:
    """
    Proses yang PPID-nya tidak ada di daftar proses.

    Bisa wajar (parent sudah exit), tapi juga ciri process hollowing di mana
    parent sengaja dimatikan. Dilaporkan sebagai pertanyaan, bukan kesimpulan.
    """
    pids = {p.get("PID") for p in processes}
    return [{"pid": p.get("PID"), "ppid": p.get("PPID"), "name": p.get("ImageFileName"),
             "note": "PPID tidak ditemukan di daftar proses -- parent sudah exit "
                     "(wajar) atau sengaja dimatikan (perlu dicek)"}
            for p in processes if p.get("PPID") not in pids and p.get("PPID")]


PERSISTENCE_LOCATIONS = (
    (r"\\start menu\\programs\\startup\\", "Folder Startup (per-user atau all-users)"),
    (r"\\appdata\\roaming\\microsoft\\windows\\start menu", "Startup per-user"),
    (r"\\programdata\\microsoft\\windows\\start menu", "Startup semua pengguna"),
    (r"\\windows\\system32\\tasks\\", "Scheduled Task"),
    (r"\\currentversion\\run", "Registry Run key"),
)


def find_persistence(cmdlines: list[dict]) -> list[dict]:
    """
    Proses yang berjalan dari lokasi persistence, dikelompokkan menurut MEKANISME.

    Berbeda dari flag_suspicious_cmdlines yang menandai per pola: di sini
    pertanyaannya "bagaimana malware ini bertahan setelah reboot", dan jawabannya
    perlu menyebut mekanismenya, bukan sekadar bahwa path-nya mencurigakan.
    """
    found = []
    for entry in cmdlines:
        args = str(entry.get("Args") or "")
        for pattern, mechanism in PERSISTENCE_LOCATIONS:
            if re.search(pattern, args, re.IGNORECASE):
                found.append({
                    "pid": entry.get("PID"), "process": entry.get("Process"),
                    "mechanism": mechanism, "path": args.strip().strip('"')[:300],
                    "binary": _executable_from_cmdline(args),
                    "confidence": "HIGH",
                })
                break
    return found


def full_memory_triage(dump_path, threat_checker=None,
                       evidence: EvidenceLog | None = None) -> dict:
    """Kombinasi plugin yang paling sering dipakai untuk triase cepat."""
    if evidence is None:
        evidence = EvidenceLog()
    if not available():
        return {"available": False,
                "error": "Volatility 3 belum terpasang (pip install volatility3)"}

    system = get_system_info(dump_path)
    if system.get("kernel_base"):
        evidence.track("memory_kernel_base", "vol -f <dump> windows.info",
                       system["kernel_base"],
                       note=f"Build {system.get('build')}, "
                            f"{'64-bit' if system.get('is_64bit') else '32-bit'}, "
                            f"{system.get('processors')} prosesor. DTB {system.get('dtb')}")

    processes = get_process_list(dump_path)
    connections = get_network_connections(dump_path)
    cmdlines = get_command_lines(dump_path)
    injected = detect_code_injection(dump_path)

    suspicious_cmd = flag_suspicious_cmdlines(cmdlines)
    orphans = find_orphan_processes(processes)
    hollowing = find_name_path_mismatch(cmdlines)
    persistence = find_persistence(cmdlines)
    for item in persistence:
        evidence.track("persistence_mechanism",
                       f"vol -f <dump> windows.cmdline --pid {item['pid']}",
                       f"{item['binary'] or item['process']} via {item['mechanism']}",
                       note=f"Proses {item['process']} (PID {item['pid']}) dijalankan dari "
                            f"lokasi persistence. Path: {item['path']}")

    # malfind mengembalikan SATU BARIS PER REGION MEMORY. Satu proses dengan 8
    # region menghasilkan 8 catatan evidence identik yang menenggelamkan appendix.
    # Dikelompokkan per proses.
    injected_by_process: dict[tuple, dict] = {}
    for item in injected:
        key = (item.get("PID"), item.get("Process"))
        entry = injected_by_process.setdefault(key, {
            "pid": item.get("PID"), "process": item.get("Process"), "region_count": 0,
            "known_false_positive": COMMON_MALFIND_FALSE_POSITIVES.get(
                str(item.get("Process")))})
        entry["region_count"] += 1

    malicious_connections = []
    if threat_checker is not None:
        for conn in connections:
            remote = conn.get("ForeignAddr")
            if remote and threat_checker.check_ip(str(remote))["is_known_malicious"]:
                malicious_connections.append(conn)
                evidence.track("memory_malicious_connection",
                               f"vol -f <dump> windows.netscan | grep {remote}",
                               f"{conn.get('Owner')} (PID {conn.get('PID')}) -> {remote}",
                               note="IP tujuan terdaftar di threat feed abuse.ch")

    for item in suspicious_cmd:
        evidence.track("memory_suspicious_cmdline",
                       f"vol -f <dump> windows.cmdline --pid {item['pid']}",
                       f"{item['process']} (PID {item['pid']})",
                       note="; ".join(item["reasons"]) + f". Command line: {item['args'][:200]}")
    for item in hollowing:
        evidence.track("memory_process_hollowing",
                       f"vol -f <dump> windows.cmdline --pid {item['pid']}",
                       f"{item['process_name']} -> {item['commandline_binary']} "
                       f"(PID {item['pid']})", note=item["note"])
    for entry in injected_by_process.values():
        evidence.track("memory_code_injection",
                       f"vol -f <dump> windows.malfind --pid {entry['pid']}",
                       f"{entry['process']} (PID {entry['pid']}), "
                       f"{entry['region_count']} region",
                       note="Region memory executable+writable tanpa berkas pendukung "
                            "di disk -- indikasi injeksi/hollowing"
                            + (f". CATATAN: {entry['known_false_positive']}"
                               if entry["known_false_positive"] else ""))

    return {
        "available": True,
        "system_info": system,
        "process_count": len(processes), "processes": processes,
        "connections": connections,
        "command_lines": cmdlines,
        "code_injection": injected,
        "code_injection_by_process": sorted(
            injected_by_process.values(),
            key=lambda e: (e["known_false_positive"] is not None, -e["region_count"])),
        "suspicious_command_lines": suspicious_cmd,
        "process_hollowing": hollowing,
        "persistence": persistence,
        "orphan_processes": orphans,
        "malicious_connections": malicious_connections,
        "external_connections": [c for c in connections
                                 if _is_external(str(c.get("ForeignAddr") or ""))],
    }


def _is_external(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_unspecified
                or addr.is_multicast or addr.is_reserved)
