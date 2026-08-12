"""
Ekstraksi file yang berhasil ditransfer utuh dari pcap — setara tab "Files" di
NetworkMiner.

Hanya berlaku untuk protokol yang tidak terenkripsi (HTTP/SMB/FTP/TFTP). Traffic
TLS tidak bisa di-carve tanpa key log.
"""
import os
from pathlib import Path

from .. import config as settings
from . import tools
from . import pcap_parser
from .hash_analyzer import analyze_file
from .timeline_builder import EvidenceLog
from .tools import run

SUSPICIOUS_EXTENSIONS = (".exe", ".dll", ".ps1", ".hta", ".vbs", ".js", ".jse",
                         ".zip", ".rar", ".7z", ".scr", ".bat", ".cmd", ".msi",
                         ".jar", ".lnk", ".iso", ".img", ".cab", ".chm")

EXPORT_PROTOCOLS = ("http", "smb", "tftp", "ftp-data", "imf")

# `--export-objects smb` ikut mengekspor NAMED PIPE RPC, bukan file. Satu pcap
# Windows biasa menghasilkan ratusan potongan '\lsarpc(107)' berukuran 260 byte.
# Kalau tidak disaring, daftar file hasil carving 100% berisi ini dan file
# sungguhan tenggelam di antaranya.
SMB_NAMED_PIPES = ("lsarpc", "srvsvc", "samr", "browser", "wkssvc", "netlogon",
                   "atsvc", "epmapper", "eventlog", "spoolss", "winreg", "svcctl",
                   "ntsvcs", "initshutdown", "lsass")

# Objek di bawah ukuran ini hampir selalu fragmen protokol, bukan berkas.
MIN_FILE_SIZE = 512


# Nama device khusus Windows. Nama objek HTTP diambil dari URL, jadi
# DIKENDALIKAN PENYERANG -- satu request ke '/nul' membuat tshark menulis berkas
# bernama 'nul', yang tidak bisa dihapus lewat API biasa dan menetap selamanya
# di direktori carving.
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", "clock$"} | {
    f"{prefix}{n}" for prefix in ("com", "lpt") for n in range(1, 10)}


def _is_protocol_artifact(name: str, size: int) -> bool:
    stem = name.lstrip("%5c\\/").split("(")[0].lower()
    return stem in SMB_NAMED_PIPES or size < MIN_FILE_SIZE


def extended_path(path: Path) -> str:
    r"""
    Bentuk '\\?\' dari sebuah path, aman untuk nama device Windows.

    Nama induknya di-resolve TERPISAH lalu nama berkas ditempelkan apa adanya.
    Ini bukan gaya-gayaan: `os.path.abspath('dir/nul')` mengembalikan `\\.\nul`
    -- fungsi itu sendiri yang meruntuhkan path jadi perangkat, sehingga path
    extended yang dibangun darinya rusak dan penghapusan gagal dengan
    'The filename, directory name, or volume label syntax is incorrect'.
    """
    return "\\\\?\\" + str(path.parent.resolve()) + "\\" + path.name


def _force_unlink(path: Path) -> None:
    r"""
    Hapus berkas, termasuk yang bernama device khusus Windows.

    `Path('dir/nul').unlink()` gagal dengan Access denied: Windows mengurai
    'nul' sebagai perangkat, bukan berkas. Prefiks '\\?\' mematikan penguraian
    itu sehingga namanya diperlakukan apa adanya.
    """
    try:
        path.unlink(missing_ok=True)
        return
    except OSError:
        pass
    if os.name == "nt":
        try:
            os.remove(extended_path(path))
        except OSError:
            pass   # sudah hilang atau memang tidak bisa dihapus; jangan gagalkan analisis


# Nama protokol di `tshark -z io,phs` tidak selalu sama dengan nama exporter-nya.
EXPORTER_REQUIRES = {"http": ("http",), "smb": ("smb", "smb2"), "tftp": ("tftp",),
                     "ftp-data": ("ftp-data", "ftp"), "imf": ("imf", "smtp")}


def extract_transferred_files(pcap_path, output_dir=None, threat_checker=None,
                              evidence: EvidenceLog | None = None,
                              protocols: dict[str, int] | None = None) -> list[dict]:
    """
    `tshark --export-objects <proto>,<dir>` -- sama seperti Wireshark
    File > Export Objects.

    Tiap protokol diekspor ke SUBFOLDER SENDIRI. Kalau http dan smb menulis ke
    direktori yang sama, file bernama sama saling menimpa dan asal-usulnya
    hilang -- padahal "file ini masuk lewat HTTP atau lewat SMB" bagian dari
    temuan, bukan detail teknis.
    """
    if evidence is None:
        evidence = EvidenceLog()
    base = Path(output_dir or (settings.STORAGE / "carved" / Path(pcap_path).stem))
    results: list[dict] = []
    skipped: dict[str, int] = {}   # dilaporkan, bukan disembunyikan
    removed: dict[str, int] = {}

    for proto in EXPORT_PROTOCOLS:
        # Tiap `--export-objects` adalah SATU PASS PENUH atas pcap. Menjalankan
        # kelimanya pada capture yang cuma berisi HTTP membuang empat pembacaan
        # utuh untuk hasil yang pasti kosong.
        if not pcap_parser.has_protocol(protocols, *EXPORTER_REQUIRES[proto]):
            continue
        proto_dir = base / proto
        proto_dir.mkdir(parents=True, exist_ok=True)
        run([tools.resolve("tshark"), "-r", str(pcap_path),
             "--export-objects", f"{proto},{proto_dir}"],
            timeout=settings.TSHARK_TIMEOUT,
            check=False)   # protokol yang tidak ada di pcap membuat tshark
                           # keluar non-zero; itu wajar, bukan kegagalan
        seen_hashes: set[str] = set()
        discard: list[Path] = []
        # os.scandir memberi ukuran berkas tanpa panggilan stat() terpisah.
        # Untuk direktori berisi puluhan ribu entry, selisihnya terasa.
        for entry in sorted(os.scandir(proto_dir), key=lambda e: e.name):
            if not entry.is_file():
                continue
            path, size = Path(entry.path), entry.stat().st_size
            # Berkas bernama device Windows tidak bisa dibaca sebagai berkas
            # biasa -- membaca 'nul' mengembalikan kosong, bukan isinya.
            if os.name == "nt" and path.stem.lower() in WINDOWS_RESERVED:
                skipped[proto] = skipped.get(proto, 0) + 1
                discard.append(path)
                continue
            if _is_protocol_artifact(entry.name, size):
                skipped[proto] = skipped.get(proto, 0) + 1
                discard.append(path)
                continue
            info = analyze_file(path, threat_checker)
            # tshark mengekspor objek yang sama berkali-kali kalau muncul di
            # beberapa response; hash identik = berkas yang sama.
            if info["exact_hashes"]["sha256"] in seen_hashes:
                discard.append(path)
                continue
            seen_hashes.add(info["exact_hashes"]["sha256"])
            suspicious = path.suffix.lower() in SUSPICIOUS_EXTENSIONS
            known_bad = bool(info.get("is_known_malicious"))
            info.update({
                "protocol": proto,
                "path": str(path),
                "is_suspicious_extension": suspicious,
                "confidence": "HIGH" if known_bad else ("MEDIUM" if suspicious else "LOW"),
                "evidence_query": f'{proto} && frame contains "{path.name[:40]}"'
                                  if proto == "http" else proto,
            })
            results.append(info)
            if known_bad or suspicious:
                evidence.track(
                    "suspicious_file_download",
                    f'http.response && http.request.uri contains "{path.name[:40]}"'
                    if proto == "http" else f"{proto} object: {path.name}",
                    f"{path.name} (sha256 {info['exact_hashes']['sha256'][:16]}...)",
                    note=("COCOK dengan hash malware di ThreatFox. " if known_bad else "")
                         + f"Ekstensi {path.suffix or '(tanpa ekstensi)'}, "
                           f"{info['file_size']} byte, tipe terdeteksi {info['file_type']}. "
                           f"File tersimpan di {path}")

        # Artefak protokol dan duplikat DIHAPUS setelah diperiksa.
        # `--export-objects http` menulis satu berkas per body HTTP: satu capture
        # web 28 MB menghasilkan 41.625 berkas untuk 27 yang benar-benar berkas,
        # dan semuanya menetap di disk. Setelah beberapa kali analisis, direktori
        # carving berisi ratusan ribu entry -- membuat direktorinya sendiri lambat
        # dibaca dan menyulitkan menemukan berkas yang penting.
        for path in discard:
            _force_unlink(path)
        removed[proto] = len(discard)

    # Direktori protokol yang kosong cuma bikin bingung saat menelusuri hasil.
    for proto in EXPORT_PROTOCOLS:
        proto_dir = base / proto
        if proto_dir.exists() and not any(proto_dir.iterdir()):
            proto_dir.rmdir()
    if base.exists() and not any(base.iterdir()):
        base.rmdir()

    if skipped or removed:
        evidence.track(
            "carving_filtered", "tshark --export-objects <proto>,<dir>",
            f"{sum(removed.values())} objek dibuang, {len(results)} berkas disimpan",
            note="Yang dibuang: fragmen <512 byte, named pipe RPC (\\lsarpc, "
                 "\\srvsvc, dst), dan duplikat berhash sama. Rincian per protokol: "
                 f"{removed}. Untuk memeriksa objek mentahnya, jalankan ulang "
                 "`tshark --export-objects` secara manual ke direktori terpisah")

    return sorted(results, key=lambda f: (f["confidence"] != "HIGH",
                                          f["confidence"] != "MEDIUM", f["filename"]))
