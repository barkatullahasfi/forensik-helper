"""
Analisis reverse engineering STATIS: overlay, resource, string terkode, dan
disassembly titik masuk.

Tidak ada berkas yang dijalankan. Semua di sini membaca struktur, bukan
mengeksekusinya -- eksekusi butuh sandbox terisolasi yang di luar lingkup alat
ini dan berbahaya kalau salah dikonfigurasi.

Yang dicari: tempat-tempat muatan biasa disembunyikan dan tidak terlihat oleh
`strings` biasa -- data setelah akhir PE, resource yang isinya berkas lain,
dan string yang dikodekan supaya lolos dari pemindaian.
"""
import base64
import re
from collections import Counter
from pathlib import Path

from .timeline_builder import EvidenceLog

# Batas ukuran untuk pemindaian yang memuat berkas ke memori.
MAX_SCAN_BYTES = 64 * 1024 * 1024
# Kunci XOR satu byte yang dicoba. 255 lintasan atas berkas beberapa ratus KB
# masih murah; untuk berkas besar pemindaian dipotong.
MAX_XOR_SCAN = 8 * 1024 * 1024

SIGNATURES = {
    b"MZ": "PE executable", b"\x7fELF": "ELF", b"PK\x03\x04": "ZIP/arsip",
    b"%PDF-": "PDF", b"Rar!": "RAR", b"7z\xbc\xaf": "7-Zip",
    b"\x1f\x8b\x08": "GZIP", b"#!": "skrip dengan shebang",
}

# Pola yang menandakan sesuatu bernilai kalau ditemukan setelah dekode.
INTERESTING = re.compile(
    rb"https?://[^\s\"'<>]{4,}|"
    rb"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|su|cn|top|xyz|icu|cc|io|me|info)\b|"
    rb"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    rb"[A-Za-z]:\\\\?[\w\\\-. ]{4,60}|"
    rb"(?:HKEY_|SOFTWARE\\\\|Software\\\\)[\w\\\-.]{4,60}", re.I)

_IPISH = re.compile(rb"^(?:\d{1,3}\.){3}\d{1,3}$")


def _valid_hits(hits: list[bytes]) -> list[str]:
    """
    Saring kecocokan yang berbentuk IP tapi oktetnya mustahil.

    Pola IP juga cocok dengan deretan angka bertitik seperti '776.669.998.776'
    -- lazim muncul dari data biner yang di-XOR asal. Melaporkannya sebagai IOC
    membuat hasil brute force XOR tidak bisa dipercaya sama sekali.
    """
    valid = []
    for hit in hits:
        if _IPISH.match(hit):
            if any(int(part) > 255 for part in hit.split(b".")):
                continue
        valid.append(hit.decode("utf-8", "replace"))
    return sorted(set(valid))


# Nama resource yang punya arti khusus: isinya bukan sumber daya UI biasa.
KNOWN_RESOURCES = {
    "SCRIPT": ("Skrip AutoIt terkompilasi",
               "Di sinilah logika dan konfigurasi program AutoIt berada, termasuk "
               "alamat C2. Ekstrak dengan Exe2Aut atau UnAutoIt — strings biasa "
               "tidak akan menampilkannya karena isinya terkompresi"),
    "PYTHONSCRIPT": ("Skrip Python tertanam", "Ekstrak lalu dekompilasi .pyc"),
    "DVCLAL": ("Penanda lisensi Delphi", None),
    "PACKAGEINFO": ("Info paket Delphi", None),
}


def _read(file_path) -> bytes:
    path = Path(file_path)
    if path.stat().st_size > MAX_SCAN_BYTES:
        return path.open("rb").read(MAX_SCAN_BYTES)
    return path.read_bytes()


def extract_overlay(file_path) -> dict:
    """
    Data yang menempel SETELAH struktur PE berakhir.

    Loader Windows mengabaikan byte di luar section terakhir, jadi apa pun yang
    ditaruh di sana ikut terbawa tanpa mengganggu jalannya program. Ini tempat
    paling lazim menyembunyikan muatan tahap kedua, arsip, atau konfigurasi --
    dan `strings` biasa tidak membedakannya dari isi program.
    """
    try:
        import pefile
        pe = pefile.PE(str(file_path), fast_load=True)
    except Exception as e:  # noqa: BLE001 -- bukan PE itu hasil yang sah
        return {"has_overlay": False, "reason": str(e)[:120]}

    end_of_pe = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections),
                    default=0)
    total = Path(file_path).stat().st_size
    size = total - end_of_pe
    if size <= 0:
        return {"has_overlay": False, "pe_ends_at": end_of_pe, "file_size": total}

    with open(file_path, "rb") as f:
        f.seek(end_of_pe)
        head = f.read(min(size, 4096))
    kind = next((label for magic, label in SIGNATURES.items() if head.startswith(magic)),
                None)
    return {
        "has_overlay": True, "offset": end_of_pe, "size": size,
        "file_size": total, "ratio": round(size / total, 3),
        "detected_type": kind,
        "entropy": round(_entropy(head), 2),
        "preview_hex": head[:64].hex(),
        "note": (f"{size} byte ({round(size / total * 100)}% berkas) berada setelah "
                 "section terakhir PE. Loader Windows tidak memuatnya, jadi program "
                 "sendiri yang harus membacanya — itu berarti data ini memang "
                 "disengaja ada di sana."),
    }


def extract_resources(file_path, output_dir=None) -> list[dict]:
    """
    Resource PE yang isinya berkas lain.

    Resource adalah tempat sah untuk ikon dan teks, tapi juga tempat lazim
    menaruh executable atau skrip. Yang dilaporkan hanya yang signature-nya
    menunjukkan berkas lain, bukan seluruh ikon dan tabel string.
    """
    try:
        import pefile
        pe = pefile.PE(str(file_path))
    except Exception:  # noqa: BLE001
        return []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return []

    found = []
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = str(entry.name or pefile.RESOURCE_TYPE.get(entry.struct.Id, entry.struct.Id))
        for level2 in getattr(entry, "directory", {}).entries or []:
            for level3 in getattr(level2, "directory", {}).entries or []:
                data_rva = level3.data.struct.OffsetToData
                size = level3.data.struct.Size
                if size < 64 or size > MAX_SCAN_BYTES:
                    continue
                blob = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                kind = next((label for magic, label in SIGNATURES.items()
                             if blob.startswith(magic)), None)
                entropy = _entropy(blob[:8192])
                name = str(level2.name or level2.struct.Id)
                known, hint = KNOWN_RESOURCES.get(name.upper(), (None, None))
                # Resource biasa (ikon, tabel string) tidak berisi signature
                # berkas lain dan entropinya sedang. Tabel string terkompresi
                # memang berentropi tinggi tanpa berarti apa-apa, jadi yang
                # dilaporkan diprioritaskan pada nama yang dikenal dan RCDATA.
                notable = known or kind or (entropy >= 7.2 and type_name != "RT_STRING")
                if not notable:
                    continue
                record = {
                    "type": type_name, "name": name, "size": size,
                    "detected_type": kind, "known_kind": known,
                    "entropy": round(entropy, 2),
                    "confidence": "HIGH" if (known or kind) else "MEDIUM",
                    "note": (f"{known}. {hint}" if known and hint else
                             known or (f"Resource berisi {kind}" if kind else
                                       "Resource berentropi tinggi — kemungkinan "
                                       "terkompresi atau terenkripsi")),
                }
                if output_dir:
                    target = Path(output_dir) / f"resource_{type_name}_{record['name']}.bin"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(blob)
                    record["extracted_to"] = str(target)
                found.append(record)
    return found


def decode_base64_blobs(data: bytes, min_length: int = 24, limit: int = 40) -> list[dict]:
    """
    String base64 yang setelah didekode berisi sesuatu yang berarti.

    Malware menyimpan URL, perintah, dan konfigurasi dalam base64 supaya lolos
    pemindaian string sederhana. Yang dilaporkan hanya yang HASIL DEKODENYA
    memuat pola menarik -- tanpa saringan itu, tiap potongan teks acak sepanjang
    24 karakter ikut terbawa.
    """
    results = []
    for match in re.finditer(rb"[A-Za-z0-9+/]{%d,}={0,2}" % min_length, data):
        blob = match.group()
        try:
            decoded = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
        except Exception:  # noqa: BLE001
            continue
        if len(decoded) < 8:
            continue
        hits = INTERESTING.findall(decoded)
        if not hits:
            continue
        results.append({
            "offset": match.start(),
            "encoded": blob[:80].decode("ascii", "ignore"),
            "decoded": decoded[:300].decode("utf-8", "replace"),
            "matches": _valid_hits(hits)[:8],
        })
        if len(results) >= limit:
            break
    return results


def brute_force_xor(data: bytes, limit: int = 20) -> list[dict]:
    """
    String yang dikodekan XOR satu byte.

    XOR satu byte adalah penyamaran termurah dan paling umum di malware
    komoditas. Karena kuncinya cuma 256 kemungkinan, mencoba semuanya jauh
    lebih murah daripada menebak -- dan yang dilaporkan hanya kunci yang
    menghasilkan URL, domain, IP, atau path yang masuk akal.
    """
    sample = data[:MAX_XOR_SCAN]
    results = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in sample)
        unique = _valid_hits(INTERESTING.findall(decoded))
        # Satu-dua kecocokan bisa kebetulan; kunci yang benar biasanya
        # memunculkan beberapa sekaligus.
        if len(unique) < 3:
            continue
        results.append({"key": key, "key_hex": f"0x{key:02x}",
                        "match_count": len(unique), "matches": unique[:10]})
        if len(results) >= limit:
            break
    return sorted(results, key=lambda r: -r["match_count"])


def disassemble_entry_point(file_path, count: int = 40) -> dict:
    """
    Instruksi pertama yang dijalankan program.

    Titik masuk memperlihatkan apa yang dilakukan program SEBELUM apa pun yang
    terlihat di strings: stub pembongkar, pemeriksaan anti-debug, atau lompatan
    langsung ke kode sebenarnya.
    """
    try:
        import capstone
        import pefile
    except ImportError:
        return {"available": False,
                "hint": "pip install capstone — disassembly titik masuk dilewati"}
    try:
        pe = pefile.PE(str(file_path))
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code = pe.get_memory_mapped_image()[entry:entry + count * 16]
        is_64 = pe.FILE_HEADER.Machine == 0x8664
        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32)
        base = pe.OPTIONAL_HEADER.ImageBase + entry
        lines = [f"0x{i.address:x}  {i.mnemonic:<8} {i.op_str}"
                 for i in md.disasm(code, base)][:count]
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)[:200]}
    return {"available": True, "architecture": "x64" if is_64 else "x86",
            "entry_rva": hex(entry), "instructions": lines}


def imphash(file_path) -> str | None:
    """
    Hash dari tabel import, dalam urutan aslinya.

    Berguna untuk MENGELOMPOKKAN sampel: dua berkas dengan imphash sama biasanya
    dibangun dari kode dan toolchain yang sama, meski hash berkasnya berbeda.
    Tidak berlaku untuk berkas ter-pack — importnya milik stub pembongkar,
    bukan milik program aslinya.
    """
    try:
        import pefile
        return pefile.PE(str(file_path), fast_load=False).get_imphash() or None
    except Exception:  # noqa: BLE001
        return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def analyze(file_path, output_dir=None, evidence: EvidenceLog | None = None) -> dict:
    """Entry point: seluruh pemeriksaan statis di atas dalam satu hasil."""
    if evidence is None:
        evidence = EvidenceLog()
    path = Path(file_path)
    data = _read(path)

    overlay = extract_overlay(path)
    resources = extract_resources(path, output_dir)
    base64_blobs = decode_base64_blobs(data)
    xor_keys = brute_force_xor(data)
    entry = disassemble_entry_point(path)
    imports_hash = imphash(path)

    if overlay.get("has_overlay") and overlay["size"] > 1024:
        evidence.track("pe_overlay", f"pefile {path.name} — offset {overlay['offset']}",
                       f"{overlay['size']} byte setelah akhir PE"
                       + (f" ({overlay['detected_type']})" if overlay["detected_type"] else ""),
                       note=overlay["note"])
    for item in resources:
        evidence.track("pe_resource", f"pefile {path.name} DIRECTORY_ENTRY_RESOURCE",
                       f"{item['type']}/{item['name']} ({item['size']} byte)",
                       note=item["note"]
                            + (f" Diekstrak ke {item['extracted_to']}"
                               if item.get("extracted_to") else ""))
    for item in base64_blobs[:10]:
        evidence.track("encoded_string", f"base64 offset {item['offset']}",
                       ", ".join(item["matches"]),
                       note=f"String base64 di dalam berkas yang setelah didekode "
                            f"memuat: {item['decoded'][:150]}")
    for item in xor_keys[:3]:
        evidence.track("xor_encoded_string", f"XOR kunci {item['key_hex']}",
                       ", ".join(item["matches"][:5]),
                       note=f"{item['match_count']} pola cocok setelah XOR dengan kunci "
                            f"{item['key_hex']}. XOR satu byte adalah penyamaran paling "
                            "umum di malware komoditas")
    if imports_hash:
        evidence.track("imphash", f"pefile {path.name} get_imphash()", imports_hash,
                       note="Dipakai mengelompokkan sampel sekeluarga. TIDAK berlaku "
                            "untuk berkas ter-pack — importnya milik stub pembongkar")

    return {
        "overlay": overlay, "resources": resources,
        "base64_strings": base64_blobs, "xor_candidates": xor_keys,
        "entry_point": entry, "imphash": imports_hash,
    }
