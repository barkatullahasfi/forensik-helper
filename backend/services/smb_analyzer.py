"""
Analisis lalu lintas SMB/SMB2: share yang diakses dan berkas yang disentuh.

SMB adalah jalur yang paling sering dipakai untuk MENARUH berkas di mesin
korban setelah akses awal didapat. pcap merekam nama share dan nama berkasnya
secara jelas -- tanpa modul ini, informasi itu tenggelam di antara ratusan frame
SMB yang isinya negosiasi protokol.
"""
from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, to_utc

# Share administratif bawaan Windows. Diaksesnya wajar; yang menarik adalah
# share NON-administratif, karena di situlah berkas bisa ditaruh dan dibaca ulang.
ADMIN_SHARES = {"ipc$", "admin$", "c$", "d$", "print$"}

# Ekstensi yang bisa DIEKSEKUSI oleh web server kalau ditaruh di direktori yang
# dilayaninya. Berkas seperti ini di dalam share = jalur eksekusi kode jarak jauh.
WEB_EXECUTABLE = (".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp", ".jspx",
                  ".cfm", ".cgi", ".pl", ".exe", ".dll")


def _unescape(value: str) -> str:
    r"""
    tshark menggandakan backslash pada field UNC.

    Nilai mentah `\\\\10.0.2.15\\IPC$` sebenarnya berarti `\\10.0.2.15\IPC$`.
    Menyalinnya apa adanya ke laporan menghasilkan path yang tidak bisa dipakai.
    """
    return value.replace("\\\\", "\\").strip()


def tree_connects(pcap_path, evidence: EvidenceLog | None = None) -> list[dict]:
    """Share yang di-mount penyerang, terurut waktu."""
    if evidence is None:
        evidence = EvidenceLog()
    rows = run_tshark_fields(
        pcap_path, "smb2.cmd==3 && smb2.flags.response==0",
        ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "smb2.tree"])

    seen, connects = set(), []
    for row in rows:
        path = _unescape(row["smb2.tree"].split(",")[0])
        if not path:
            continue
        share = path.rstrip("\\").rsplit("\\", 1)[-1]
        entry = {
            "unc_path": path,
            "share": share,
            "is_admin_share": share.lower() in ADMIN_SHARES,
            "frame_number": _int(row["frame.number"]),
            "timestamp": _float(row["frame.time_epoch"]),
            "time_utc": to_utc(_float(row["frame.time_epoch"])),
            "src_ip": row["ip.src"].split(",")[0],
            "dst_ip": row["ip.dst"].split(",")[0],
            "evidence_query": f'smb2.cmd==3 && smb2.tree contains "{share}"',
        }
        connects.append(entry)
        if path not in seen:
            seen.add(path)
            evidence.track(
                "smb_tree_connect", entry["evidence_query"], path,
                note=f"{entry['src_ip']} me-mount share pada {entry['time_utc']} "
                     f"(frame {entry['frame_number']})."
                     + (" Share administratif bawaan Windows."
                        if entry["is_admin_share"] else
                        " Share NON-administratif -- di sinilah berkas bisa ditaruh."))
    return connects


def file_operations(pcap_path, evidence: EvidenceLog | None = None) -> list[dict]:
    """
    Berkas yang disentuh lewat SMB, beserta apakah namanya bisa dieksekusi web.

    tshark memunculkan nama berkas pada SMB2 Create. Nama seperti '<share>' dan
    daftar dipisah koma adalah artefak enumerasi direktori, bukan berkas tunggal
    -- keduanya dipisahkan supaya tidak dilaporkan sebagai berkas yang diunggah.
    """
    if evidence is None:
        evidence = EvidenceLog()
    rows = run_tshark_fields(
        pcap_path, "smb2.filename",
        ["frame.number", "frame.time_epoch", "ip.src", "smb2.filename", "smb2.cmd"])

    files: dict[str, dict] = {}
    for row in rows:
        raw = _unescape(row["smb2.filename"])
        if not raw or raw.startswith("<"):
            continue
        # Satu frame bisa memuat banyak nama (hasil directory listing).
        for name in raw.split(","):
            name = name.strip()
            if not name or name in (".", ".."):
                continue
            entry = files.setdefault(name, {
                "filename": name,
                "basename": name.rsplit("\\", 1)[-1],
                "access_count": 0,
                "first_seen": _float(row["frame.time_epoch"]),
                "first_frame": _int(row["frame.number"]),
                "accessed_by": set(),
            })
            entry["access_count"] += 1
            entry["accessed_by"].add(row["ip.src"].split(",")[0])

    results = []
    for entry in files.values():
        basename = entry["basename"].lower()
        executable = basename.endswith(WEB_EXECUTABLE)
        record = {
            **entry,
            "accessed_by": sorted(entry["accessed_by"]),
            "time_utc": to_utc(entry["first_seen"]),
            "is_web_executable": executable,
            "confidence": "HIGH" if executable else "LOW",
            "evidence_query": f'smb2.filename contains "{entry["basename"]}"',
        }
        results.append(record)
        if executable:
            evidence.track(
                "smb_web_executable", record["evidence_query"], entry["basename"],
                note=f"Berkas dengan ekstensi yang DAPAT DIEKSEKUSI web server "
                     f"disentuh lewat SMB pada {record['time_utc']} "
                     f"(frame {entry['first_frame']}, {entry['access_count']}x diakses). "
                     "Kalau share ini dilayani web server, ini jalur eksekusi kode "
                     "jarak jauh -- verifikasi dengan mencari request HTTP ke nama "
                     "berkas yang sama.")
    return sorted(results, key=lambda f: (not f["is_web_executable"], f["first_seen"] or 0))


def analyze(pcap_path, evidence: EvidenceLog | None = None) -> dict:
    if evidence is None:
        evidence = EvidenceLog()
    connects = tree_connects(pcap_path, evidence)
    files = file_operations(pcap_path, evidence)
    non_admin = [c for c in connects if not c["is_admin_share"]]
    return {
        "tree_connects": connects,
        "shares_accessed": sorted({c["unc_path"] for c in connects}),
        "non_admin_shares": sorted({c["unc_path"] for c in non_admin}),
        "files": files,
        "web_executables": [f for f in files if f["is_web_executable"]],
    }


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
