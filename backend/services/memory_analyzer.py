"""
Wrapper Volatility 3 untuk RAM dump.

Beda dengan disk image (data persisten), RAM dump menangkap STATE sistem tepat
saat di-dump: proses berjalan, koneksi aktif, command line, bahkan kode yang
tidak pernah menyentuh disk.
"""
import json
import re
from pathlib import Path

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


# Binary Windows sah yang bisa dipakai menjalankan kode pihak ketiga
# ("living off the land"). Yang dicari bukan keberadaannya -- semuanya bawaan
# Windows dan lazim -- melainkan APA yang mereka jalankan.
LOLBINS = {
    "rundll32.exe": ("T1218.011", "Rundll32"),
    "regsvr32.exe": ("T1218.010", "Regsvr32"),
    "mshta.exe": ("T1218.005", "Mshta"),
    "msiexec.exe": ("T1218.007", "Msiexec"),
    "installutil.exe": ("T1218.004", "InstallUtil"),
    "regasm.exe": ("T1218.009", "Regsvcs/Regasm"),
    "regsvcs.exe": ("T1218.009", "Regsvcs/Regasm"),
    "cmstp.exe": ("T1218.003", "CMSTP"),
    "odbcconf.exe": ("T1218.008", "Odbcconf"),
    "mavinject.exe": ("T1218.013", "Mavinject"),
    "verclsid.exe": ("T1218.012", "Verclsid"),
    "hh.exe": ("T1218.001", "Compiled HTML File"),
    "control.exe": ("T1218.002", "Control Panel"),
    "mmc.exe": ("T1218.014", "MMC"),
    "certutil.exe": ("T1105", "Ingress Tool Transfer"),
    "bitsadmin.exe": ("T1197", "BITS Jobs"),
    "wmic.exe": ("T1047", "Windows Management Instrumentation"),
    "cscript.exe": ("T1059.005", "Visual Basic"),
    "wscript.exe": ("T1059.005", "Visual Basic"),
    "powershell.exe": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
}

# Berkas yang, bila dijalankan LEWAT LOLBin, hampir selalu berarti muatan tahap
# kedua -- bukan pemakaian normal utilitas tersebut.
PAYLOAD_EXTENSIONS = (".dll", ".ocx", ".cpl", ".hta", ".sct", ".xsl", ".vbs",
                      ".js", ".jse", ".wsf", ".ps1", ".bat", ".cmd", ".scr", ".exe")

# Host UNC boleh memuat '@' dan port: '\\45.9.74.32@8888\davwwwroot\' adalah
# sintaks WebDAV yang lazim dipakai mengambil muatan lewat HTTP, dan justru
# bentuk itulah yang sering dipakai penyerang untuk menghindari SMB yang diblokir.
# Tanpa '@' dan ':' di kelas karakter, ekstraksi share gagal DIAM-DIAM.
UNC_PATTERN = re.compile(r"\\\\[\w.\-@:]+\\[\w.$\-]+(?:\\[^\s\"'<>|,]*)?")


def get_user_sids(dump_path) -> dict[int, dict]:
    """
    windows.getsids — pemilik tiap proses.

    Nama pengguna TIDAK ada di pslist maupun cmdline; ia hanya keluar dari
    plugin ini. Tanpa itu, pertanyaan "akun mana yang dipakai proses berbahaya"
    tidak terjawab sama sekali, padahal itu penentu ruang lingkup insiden.
    """
    rows = run_plugin(dump_path, "windows.getsids.GetSIDs")
    owners: dict[int, dict] = {}
    for row in rows:
        pid, name = row.get("PID"), str(row.get("Name") or "")
        if pid is None or not name:
            continue
        entry = owners.setdefault(int(pid), {"sids": [], "user": None})
        entry["sids"].append({"sid": row.get("SID"), "name": name})
        # SID akun pengguna berbentuk S-1-5-21-<domain>-<RID>; grup bawaan dan
        # SID sistem tidak berpola itu, jadi tidak boleh dianggap nama pengguna.
        sid = str(row.get("SID") or "")
        if sid.startswith("S-1-5-21-") and "\\" in name and entry["user"] is None:
            entry["user"] = name
        elif sid.startswith("S-1-5-21-") and entry["user"] is None and " " not in name:
            entry["user"] = name
    return owners


def find_lolbin_execution(cmdlines: list[dict]) -> list[dict]:
    """
    Utilitas Windows sah yang dipakai menjalankan berkas lain.

    Keberadaan rundll32 atau mshta di daftar proses itu normal. Yang menandakan
    serangan adalah SASARANNYA: berkas di direktori pengguna, share jaringan,
    atau berekstensi muatan.
    """
    findings = []
    for entry in cmdlines:
        process = str(entry.get("Process") or "").lower()
        args = str(entry.get("Args") or "")
        if not args:
            continue

        targets = [t for t in re.findall(r"[^\s\"',]+", args)
                   if t.lower().endswith(PAYLOAD_EXTENSIONS)]
        unc = UNC_PATTERN.findall(args)
        if not targets and not unc:
            continue

        # LOLBin yang dipakai bisa berupa proses ITU SENDIRI, atau disebut DI
        # DALAM command line-nya. Kasus kedua sangat lazim dan mudah terlewat:
        #   powershell.exe -windowstyle hidden ... ; rundll32 \\host\share\x.dll,entry
        # Proses yang terdaftar adalah powershell, tapi yang mengeksekusi muatan
        # tahap kedua adalah rundll32 -- dan sub-technique MITRE-nya ikut yang
        # kedua, bukan yang pertama.
        used = []
        if process in LOLBINS:
            used.append((process, "proses itu sendiri"))
        for binary in LOLBINS:
            stem = binary[:-4]
            if binary == process:
                continue
            if re.search(rf"(?<![\w.]){re.escape(stem)}(?:\.exe)?(?![\w.])", args, re.I):
                used.append((binary, "dipanggil di dalam command line"))
        if not used:
            continue

        for binary, how in used:
            technique, name = LOLBINS[binary]
            # Nama utilitas yang MENJALANKAN, dan nama proses itu sendiri, bukan
            # muatan. Tanpa penyaringan ini 'rundll32 ... 3435.dll' dilaporkan
            # seolah rundll32 menjalankan powershell.exe.
            excluded = {binary, process}
            own = [t for t in targets if Path(t).name.lower() not in excluded]
            findings.append({
                "pid": entry.get("PID"), "process": entry.get("Process"),
                "lolbin": binary, "invocation": how,
                "mitre_technique": technique, "mitre_name": name,
                "targets": own, "unc_paths": unc,
                "args": args[:400],
                "confidence": "HIGH" if (unc or own) else "MEDIUM",
                "note": f"{binary} ({how}) dipakai menjalankan "
                        f"{', '.join(own or unc)}. MITRE {technique} ({name}).",
            })
    return findings


def extract_unc_paths(cmdlines: list[dict]) -> list[dict]:
    """
    Path UNC di command line: berkas yang diambil dari server jarak jauh.

    Menandakan muatan tidak berasal dari mesin ini, dan menyebut nama server
    beserta share-nya -- keduanya IOC yang bisa langsung dicari di jaringan.
    """
    found: dict[str, dict] = {}
    for entry in cmdlines:
        for path in UNC_PATTERN.findall(str(entry.get("Args") or "")):
            parts = path.strip("\\").split("\\")
            record = found.setdefault(path, {
                "unc_path": path,
                "host": parts[0] if parts else None,
                "share": parts[1] if len(parts) > 1 else None,
                "used_by": [],
            })
            record["used_by"].append({"pid": entry.get("PID"),
                                      "process": entry.get("Process")})
    return list(found.values())


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


def build_process_tree(processes: list[dict], owners: dict | None = None,
                       cmdlines: list[dict] | None = None) -> list[dict]:
    """
    Rantai induk tiap proses, bukan sekadar nomor PPID.

    "PPID 2820" tidak berarti apa-apa sendirian. Yang menjelaskan alur serangan
    adalah rantainya: explorer.exe -> cmd.exe -> rundll32.exe. Proses induk yang
    sudah tidak ada juga dinyatakan, karena itu sendiri sebuah temuan.
    """
    by_pid = {p.get("PID"): p for p in processes if p.get("PID") is not None}
    args_by_pid = {c.get("PID"): c.get("Args") for c in (cmdlines or [])}
    owners = owners or {}

    tree = []
    for proc in processes:
        pid, ppid = proc.get("PID"), proc.get("PPID")
        chain, seen = [], set()
        current = ppid
        while current in by_pid and current not in seen:
            seen.add(current)
            chain.append(f"{by_pid[current].get('ImageFileName')} ({current})")
            current = by_pid[current].get("PPID")
        tree.append({
            "pid": pid, "ppid": ppid,
            "name": proc.get("ImageFileName"),
            "parent_name": (by_pid[ppid].get("ImageFileName") if ppid in by_pid
                            else None),
            "parent_exists": ppid in by_pid,
            "ancestry": " <- ".join(chain) or "(induk tidak ada di dump)",
            "user": (owners.get(pid) or {}).get("user"),
            "create_time": proc.get("CreateTime"),
            "args": args_by_pid.get(pid),
        })
    return tree


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

    owners = get_user_sids(dump_path)
    suspicious_cmd = flag_suspicious_cmdlines(cmdlines)
    orphans = find_orphan_processes(processes)
    hollowing = find_name_path_mismatch(cmdlines)
    lolbins = find_lolbin_execution(cmdlines)
    unc_paths = extract_unc_paths(cmdlines)
    tree = build_process_tree(processes, owners, cmdlines)
    by_pid = {t["pid"]: t for t in tree}

    # Nama pengguna dan rantai induk ditempelkan ke tiap temuan: pertanyaan
    # "akun mana" dan "apa induknya" selalu menyusul begitu sebuah proses
    # dicurigai, dan mencarinya manual di daftar 100+ proses itu pekerjaan sia-sia.
    for group in (suspicious_cmd, hollowing, lolbins):
        for item in group:
            context = by_pid.get(item.get("pid")) or {}
            item["user"] = context.get("user")
            item["ppid"] = context.get("ppid")
            item["parent_name"] = context.get("parent_name")
            item["ancestry"] = context.get("ancestry")

    for item in lolbins:
        evidence.track(
            "lolbin_execution", f"vol -f <dump> windows.cmdline --pid {item['pid']}",
            f"{item['process']} (PID {item['pid']}) menjalankan "
            f"{', '.join(item['targets'] or item['unc_paths'])}",
            note=item["note"] + f" Induk: {item.get('parent_name')} "
                 f"(PPID {item.get('ppid')}). Pengguna: {item.get('user') or 'tidak diketahui'}.")
    for item in unc_paths:
        evidence.track(
            "remote_share_access", f"vol -f <dump> windows.cmdline",
            item["unc_path"],
            note=f"Share '{item['share']}' pada host '{item['host']}' diakses oleh "
                 + ", ".join(f"{u['process']} (PID {u['pid']})" for u in item["used_by"])
                 + ". Muatan berasal dari luar mesin ini.")
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
    for conn in notable_connections(connections):
        if conn["confidence"] == "HIGH":
            evidence.track(
                "suspicious_outbound_connection", conn["evidence_query"],
                f"{conn['process']} (PID {conn['pid']}) -> {conn['foreign']}",
                note="; ".join(conn["reasons"]) + f". State: {conn['state']}")

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
        "lolbin_execution": lolbins,
        "remote_shares": unc_paths,
        "process_tree": tree,
        "users": {str(pid): info.get("user") for pid, info in owners.items()
                  if info.get("user")},
        "orphan_processes": orphans,
        "malicious_connections": malicious_connections,
        "notable_connections": notable_connections(connections),
        "external_connections": [c for c in connections
                                 if _is_external(str(c.get("ForeignAddr") or ""))],
    }


# Proses server: menerima koneksi adalah tugasnya, MEMULAI koneksi keluar bukan.
SERVER_PROCESSES = ("w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe", "tomcat.exe",
                    "inetinfo.exe", "java.exe", "php-cgi.exe", "node.exe")

# Port yang jarang dipakai lalu lintas keluar yang sah.
SUSPICIOUS_PORTS = {1337, 4444, 4445, 4443, 5555, 6666, 6667, 7777, 8443, 8888,
                    9001, 9002, 31337, 50050}


def notable_connections(connections: list[dict]) -> list[dict]:
    """
    Koneksi yang layak dilihat, beserta ALASANNYA.

    Menyaring hanya ke "IP eksternal" adalah kesalahan yang mahal: pada lab,
    jaringan internal, atau serangan lateral, penyerang berada di alamat PRIVAT.
    Reverse shell ke 10.0.2.4 tersaring keluar justru karena ia tetangga sesubnet
    -- temuan terpenting jadi tak terlihat sama sekali.

    Jadi yang dipakai bukan "eksternal atau bukan", melainkan apakah koneksinya
    janggal: siapa yang memulainya, ke port berapa, dan ke mana.
    """
    notable = []
    for conn in connections:
        owner = str(conn.get("Owner") or "").lower()
        foreign = str(conn.get("ForeignAddr") or "")
        port = conn.get("ForeignPort")
        state = str(conn.get("State") or "")
        if not foreign or foreign in ("0.0.0.0", "::", "*") or state == "LISTENING":
            continue

        reasons = []
        if owner in SERVER_PROCESSES:
            reasons.append(f"{conn.get('Owner')} adalah proses SERVER — memulai "
                           "koneksi keluar adalah pembalikan peran, pola reverse shell")
        if port in SUSPICIOUS_PORTS:
            reasons.append(f"port {port} jarang dipakai lalu lintas keluar yang sah")
        if _is_external(foreign):
            reasons.append("tujuan di luar jaringan lokal")
        if not reasons:
            continue
        notable.append({
            "process": conn.get("Owner"), "pid": conn.get("PID"),
            "local": f"{conn.get('LocalAddr')}:{conn.get('LocalPort')}",
            "foreign": f"{foreign}:{port}", "foreign_ip": foreign, "port": port,
            "state": state or None,
            "confidence": "HIGH" if owner in SERVER_PROCESSES or port in SUSPICIOUS_PORTS
                          else "MEDIUM",
            "reasons": reasons,
            "evidence_query": f"ip.addr=={foreign} && tcp.port=={port}",
        })
    order = {"HIGH": 0, "MEDIUM": 1}
    return sorted(notable, key=lambda c: (order.get(c["confidence"], 9), c["process"] or ""))


def _is_external(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_unspecified
                or addr.is_multicast or addr.is_reserved)
