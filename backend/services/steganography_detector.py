"""
Deteksi steganografi: file ter-embed, LSB, dan pesan berpassword.

Tools ini mempercepat DETEKSI kemungkinan stego, bukan menjamin ekstraksi
berhasil. Password custom yang tidak ada di wordlist tetap butuh insight manual.
"""
import re
from pathlib import Path

from .. import config as settings
from . import tools
from .timeline_builder import EvidenceLog
from .tools import run

COMMON_PASSWORDS = ["", "password", "123456", "admin", "stego", "secret",
                    "hidden", "flag", "steghide", "12345", "qwerty"]

# Signature berkas lain yang menarik kalau muncul TERSISIP di dalam berkas lain.
#
# Signature pendek TIDAK BOLEH dipercaya begitu saja. 'MZ' hanya 2 byte, jadi
# muncul acak rata-rata sekali per 65 KB data biner apa pun: satu JPEG 3,5 MB
# menghasilkan puluhan "PE executable ditemukan" yang seluruhnya palsu. Karena
# itu tiap signature pendek punya validator struktur, dan yang tidak lolos
# validasi tidak dilaporkan sama sekali.
EMBEDDED_SIGNATURES = {
    b"PK\x03\x04": "ZIP archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"\x7fELF": "ELF executable",
    b"%PDF-": "PDF document",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"GIF89a": "GIF image",
    b"MZ": "DOS/PE executable",
    b"\x1f\x8b\x08": "GZIP",
}

# Panjang minimum agar sebuah signature dianggap cukup spesifik tanpa validator.
MIN_SIGNATURE_LEN = 4


def _valid_pe(data: bytes, offset: int) -> bool:
    """
    'MZ' saja tidak membuktikan apa pun. PE yang sah menyimpan offset header PE
    pada e_lfanew (4 byte little-endian di +0x3C), dan di situ harus ada 'PE\\0\\0'.
    """
    if offset + 0x40 > len(data):
        return False
    e_lfanew = int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
    if not (0x40 <= e_lfanew < 0x10000000) or offset + e_lfanew + 4 > len(data):
        return False
    return data[offset + e_lfanew:offset + e_lfanew + 4] == b"PE\x00\x00"


def _valid_gzip(data: bytes, offset: int) -> bool:
    """Byte flag GZIP hanya memakai 5 bit terendah; sisanya wajib nol."""
    return offset + 4 <= len(data) and data[offset + 3] & 0xE0 == 0


VALIDATORS = {b"MZ": _valid_pe, b"\x1f\x8b\x08": _valid_gzip}


def _read_scannable(file_path) -> bytes | None:
    """
    Muat berkas untuk dipindai, atau None kalau terlalu besar.

    Scanner ini membaca berkas SEKALIGUS ke memori. Tanpa batas, satu disk image
    atau RAM dump multi-GB membuat proses kehabisan RAM -- bukan hasil analisis
    yang buruk, tapi crash.
    """
    if Path(file_path).stat().st_size > settings.MAX_INMEMORY_SCAN_BYTES:
        return None
    return Path(file_path).read_bytes()


def scan_embedded_signatures(file_path, limit: int = 40) -> list[dict]:
    """
    Cari signature berkas lain di dalam berkas — versi mandiri dari binwalk.

    Ditulis sendiri (bukan wajib binwalk) karena inilah pemeriksaan pertama yang
    selalu perlu: sering "steganografi" ternyata cuma arsip yang disisipkan
    biasa, dan itu ketahuan tanpa tool tambahan apa pun.
    """
    data = _read_scannable(file_path)
    if data is None:
        return [{"skipped": "berkas terlalu besar untuk dipindai di memori; "
                            "pakai binwalk langsung untuk evidence sebesar ini"}]
    findings = []
    for signature, label in EMBEDDED_SIGNATURES.items():
        validator = VALIDATORS.get(signature)
        if len(signature) < MIN_SIGNATURE_LEN and validator is None:
            continue   # terlalu pendek untuk dipercaya tanpa validasi struktur
        start = 0
        while len(findings) < limit:
            index = data.find(signature, start)
            if index == -1:
                break
            start = index + 1
            if index == 0:
                continue   # offset 0 adalah berkas itu sendiri, bukan sisipan
            if validator and not validator(data, index):
                continue
            findings.append({
                "offset": index, "offset_hex": hex(index), "type": label,
                "validated": validator is not None,
                "note": f"{label} pada offset {hex(index)} ({index} byte dari awal)"
                        + (" -- struktur header terverifikasi" if validator else ""),
            })
    return sorted(findings, key=lambda f: f["offset"])


# Penanda akhir yang WAJIB ada di tiap format. Kuncinya signature awal berkas,
# supaya ketiadaan penanda bisa dibedakan dari "format ini memang tidak punya".
END_MARKERS = {
    b"\xff\xd8\xff": (b"\xff\xd9", "JPEG EOI"),
    b"\x89PNG\r\n\x1a\n": (b"IEND\xaeB`\x82", "PNG IEND"),
    b"GIF8": (b"\x00\x3b", "GIF trailer"),
}


def check_trailing_data(file_path) -> dict | None:
    """
    Data setelah penanda akhir berkas. Tempat persembunyian paling klasik:
    viewer gambar berhenti di EOF, sisanya tidak pernah terlihat.

    Penanda yang HILANG sama pentingnya dengan data setelahnya. Berkas yang
    penanda akhirnya dibuang membuat pemeriksaan ini kehilangan titik ukur, dan
    versi lama modul ini menjawabnya dengan diam -- persis hasil yang sama
    dengan berkas yang memang bersih. Padahal tiap JPEG sah berakhir di FFD9:
    ketiadaannya sendiri sudah temuan.
    """
    data = _read_scannable(file_path)
    if data is None:
        return None
    for signature, (marker, name) in END_MARKERS.items():
        if not data.startswith(signature):
            continue
        index = data.rfind(marker)
        if index == -1:
            tail = data[-96:]
            return {"marker": name, "marker_missing": True,
                    "trailing_bytes": None,
                    "preview": tail.hex(), "preview_ascii": _printable(tail),
                    "note": f"Penanda akhir {name} TIDAK ADA sama sekali. Berkas ini "
                            "terpotong atau sengaja diubah -- dan ekor berkasnya "
                            "adalah tempat pertama yang harus diperiksa. Isi 96 byte "
                            "terakhir ditampilkan di preview."}
        end = index + len(marker)
        if len(data) > end + 8:
            return {"marker": name, "marker_missing": False,
                    "trailing_bytes": len(data) - end,
                    "preview": data[end:end + 64].hex(),
                    "preview_ascii": _printable(data[end:end + 64]),
                    "note": f"Ada {len(data) - end} byte setelah {name} -- "
                            "data setelah akhir berkas resmi"}
        return None
    return None


def _printable(chunk: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def extract_strings(file_path, min_length: int = 6, limit: int = 200) -> list[str]:
    """String printable ASCII + UTF-16LE, tanpa binary `strings` (tidak ada di Windows)."""
    data = _read_scannable(file_path)
    if data is None:
        return []
    found = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_length, data)]
    found += [m.decode("utf-16-le", "ignore")
              for m in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length, data)]
    return found[:limit]


# URL skema/namespace yang SELALU ada di berkas media -- bukan temuan.
BORING_URL_HINTS = ("ns.adobe.com", "w3.org", "iec.ch", "purl.org", "npes.org",
                    "openxmlformats.org", "schemas.microsoft.com", "xmlns",
                    "color.org", "sRGB", "apache.org", "gnu.org/licenses")

INTERESTING_KEYWORDS = ("flag{", "ctf{", "password", "passwd", "secret", "token",
                        "-----BEGIN", "http://", "https://")


def _interesting_strings(file_path, limit: int = 20) -> list[str]:
    """
    String yang layak dilihat manusia.

    Filter kata kunci saja tidak cukup: setiap JPEG hasil Adobe memuat belasan
    URL namespace XMP yang cocok 'http://' dan menenggelamkan temuan asli.
    """
    out = []
    for text in extract_strings(file_path):
        lowered = text.lower()
        if not any(k in lowered for k in INTERESTING_KEYWORDS):
            continue
        if any(b.lower() in lowered for b in BORING_URL_HINTS):
            continue
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# Kosakata yang memang tinggal di metadata gambar. Bukan untuk membuang temuan
# sembarangan -- hanya yang benar-benar selalu ada di berkas media normal.
BORING_TEXT_HINTS = BORING_URL_HINTS + (
    "xmpmeta", "xpacket", "rdf:", "dc:title", "photoshop:", "xmp:", "tiff:",
    "exif:", "crs:", "stEvt:", "stRef:", "Adobe", "JFIF", "Exif", "Ducky",
    "ICC Profile", "IEC 61966", "Copyright (c)", "Windows Photo", "Picasa",
    "Created with", "GIMP", "ImageMagick", "Lightroom", "CREATOR:",
)

# Panjang minimum sebuah kalimat. Di bawah ini, nama field metadata dan potongan
# tabel Huffman yang kebetulan terbaca ikut terjaring.
MIN_READABLE_RUN = 24


def readable_text(file_path, min_length: int = MIN_READABLE_RUN,
                  limit: int = 20) -> list[dict]:
    """
    Kalimat terbaca di dalam berkas yang isinya terkompresi.

    Ini aturan umumnya, dan pencocokan kata kunci hanyalah pelengkapnya. Data
    JPEG/PNG/audio yang sudah dikompresi tidak menghasilkan kalimat: satu
    kalimat utuh di dalamnya berarti seseorang menaruhnya di sana. Aturan ini
    berlaku TANPA perlu menebak kata kuncinya lebih dulu.

    Daftar kata kunci sendiri tidak akan pernah cukup. Pesan
    "This is a hidden string at the EOF" tidak memuat 'flag', 'secret', maupun
    'password' -- dan karena itu lolos sepenuhnya dari penyaring berbasis kata.
    """
    data = _read_scannable(file_path)
    if data is None:
        return []
    results = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_length, data):
        text = match.group().decode("ascii")
        if any(hint.lower() in text.lower() for hint in BORING_TEXT_HINTS):
            continue
        # Rasio huruf: memisahkan kalimat dari deretan simbol atau base64 yang
        # kebetulan panjang. Kalimat manusia didominasi huruf dan spasi.
        letters = sum(1 for c in text if c.isalpha() or c.isspace())
        ratio = letters / len(text)
        if ratio < 0.6 or " " not in text.strip():
            continue
        lowered = text.lower()
        results.append({
            "offset": match.start(), "offset_hex": hex(match.start()),
            "text": text[:300], "letter_ratio": round(ratio, 2),
            "has_keyword": any(k in lowered for k in INTERESTING_KEYWORDS),
            "note": "Teks terbaca di dalam data terkompresi. Berkas gambar/audio "
                    "tidak menghasilkan kalimat dengan sendirinya.",
        })
        if len(results) >= limit:
            break
    return sorted(results, key=lambda r: (not r["has_keyword"], -len(r["text"])))


def run_binwalk_scan(file_path) -> list[dict]:
    if not tools.is_available("binwalk"):
        return [{"skipped": "binwalk tidak terpasang (pip install binwalk)"}]
    out = run([tools.resolve("binwalk"), str(file_path)], timeout=180, check=False)
    entries = []
    for line in out.splitlines():
        match = re.match(r"^(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+)$", line.strip())
        if match:
            entries.append({"offset": int(match.group(1)),
                            "offset_hex": "0x" + match.group(2),
                            "description": match.group(3).strip()})
    return entries


def run_zsteg_scan(file_path) -> list[dict]:
    if not tools.is_available("zsteg"):
        return [{"skipped": "zsteg tidak tersedia (butuh Ruby; di Windows perlu "
                            "RubyInstaller manual)"}]
    out = run([tools.resolve("zsteg"), "-a", str(file_path)], timeout=300, check=False)
    return [{"finding": line.strip()} for line in out.splitlines() if line.strip()]


def try_steghide_extract(file_path, output_dir, wordlist: list[str] | None = None) -> dict:
    """
    `-xf` WAJIB: tanpa itu steghide menulis hasil ekstraksi ke NAMA FILE ASLI
    yang tersimpan DI DALAM stego, relatif terhadap direktori kerja proses --
    artinya berkas yang dikendalikan penyusup menentukan lokasi tulis.
    """
    if not tools.is_available("steghide"):
        return {"skipped": "steghide tidak tersedia di platform ini (tidak ada build "
                           "Windows resmi) -- lihat fallback WSL di spec 11.3"}
    passwords = wordlist or COMMON_PASSWORDS
    out_file = Path(output_dir) / "steghide_extracted.bin"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    for password in passwords:
        try:
            run([tools.resolve("steghide"), "extract", "-sf", str(file_path),
                 "-p", password, "-xf", str(out_file), "-f"], timeout=60)
        except RuntimeError:
            continue   # password salah = exit non-zero, itu hasil yang wajar
        return {"success": True, "password_used": password or "(kosong)",
                "extracted_to": str(out_file)}
    return {"success": False, "tried_passwords": len(passwords),
            "note": "Password di luar wordlist tidak akan terpecahkan otomatis -- "
                    "petunjuknya biasanya ada di soal lain"}


def full_scan(file_path, file_type: str = "", output_dir=None,
              evidence: EvidenceLog | None = None) -> dict:
    """Orkestrasi semua teknik sesuai tipe berkas."""
    if evidence is None:
        evidence = EvidenceLog()
    path = Path(file_path)
    output_dir = Path(output_dir or path.parent / f"{path.stem}_stego")

    result = {
        "embedded_signatures": scan_embedded_signatures(path),
        "trailing_data": check_trailing_data(path),
        "binwalk": run_binwalk_scan(path),
        "zsteg": None,
        "steghide": None,
        "interesting_strings": _interesting_strings(path),
        "readable_text": readable_text(path),
    }
    if "png" in file_type or "bmp" in file_type:
        result["zsteg"] = run_zsteg_scan(path)
    if any(t in file_type for t in ("jpeg", "jpg", "bmp", "wav", "audio")):
        result["steghide"] = try_steghide_extract(path, output_dir)

    for item in result["embedded_signatures"]:
        evidence.track("embedded_file", f"binwalk {path.name}", item["type"],
                       note=item["note"])
    trailing = result["trailing_data"]
    if trailing:
        evidence.track(
            "missing_end_marker" if trailing["marker_missing"] else "trailing_data",
            f"xxd {path.name} | tail",
            (f"{trailing['marker']} tidak ada" if trailing["marker_missing"]
             else f"{trailing['trailing_bytes']} byte"),
            note=trailing["note"] + f" Ekor berkas: {trailing['preview_ascii']}")
    for item in result["readable_text"]:
        evidence.track("readable_text_in_media", f"strings {path.name}",
                       item["text"][:120],
                       note=f"Offset {item['offset_hex']}. {item['note']}"
                            + (" Memuat kata kunci yang lazim dipakai di soal."
                               if item["has_keyword"] else ""))
    if result["steghide"] and result["steghide"].get("success"):
        evidence.track("steghide_extracted",
                       f"steghide extract -sf {path.name} -p '{result['steghide']['password_used']}'",
                       result["steghide"]["extracted_to"],
                       note=f"Password: {result['steghide']['password_used']}")
    return result
