"""
Ekstraksi metadata lewat exiftool: EXIF foto, metadata dokumen, GPS, authorship.
"""
import json
from datetime import datetime

from . import tools
from .timeline_builder import EvidenceLog
from .tools import run

EDITING_SOFTWARE = ("Photoshop", "GIMP", "Lightroom", "Paint.NET", "Affinity",
                    "Snapseed", "Pixlr", "Canva", "Illustrator", "Inkscape")


def available() -> bool:
    return tools.is_available("exiftool")


def extract_all_metadata(file_path) -> dict:
    """
    `-G` memberi prefix grup ('EXIF:GPSLatitude'), `-n` memberi nilai NUMERIK.

    Tanpa `-n`, GPSLatitude keluar sebagai string derajat-menit-detik
    ("6 deg 12' 30.00\" S") yang tidak bisa langsung dipakai float() untuk peta.
    """
    if not available():
        return {"error": "exiftool tidak terpasang"}
    out = run([tools.resolve("exiftool"), "-json", "-G", "-n", "-a", "-u", str(file_path)],
              timeout=120, check=False)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"error": "exiftool tidak mengembalikan JSON yang valid"}
    return data[0] if data else {}


def _get(metadata: dict, *names):
    """Cari field dengan/tanpa prefix grup -- exiftool memberi prefix hanya dengan -G."""
    for name in names:
        for key, value in metadata.items():
            if key == name or key.split(":")[-1] == name:
                return value
    return None


def extract_gps_coordinates(metadata: dict) -> dict | None:
    lat = _get(metadata, "GPSLatitude")
    lon = _get(metadata, "GPSLongitude")
    if lat is None or lon is None:
        return None
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    # Dengan -n exiftool sudah memberi tanda negatif untuk S/W, tapi sebagian
    # format menyimpan besaran positif + field Ref terpisah.
    if str(_get(metadata, "GPSLatitudeRef") or "").upper().startswith("S") and lat > 0:
        lat = -lat
    if str(_get(metadata, "GPSLongitudeRef") or "").upper().startswith("W") and lon > 0:
        lon = -lon
    return {"latitude": lat, "longitude": lon,
            "altitude": _get(metadata, "GPSAltitude"),
            "timestamp": _get(metadata, "GPSDateTime", "DateTimeOriginal"),
            "maps_url": f"https://www.google.com/maps?q={lat},{lon}"}


def extract_document_authorship(metadata: dict) -> dict:
    return {
        "author": _get(metadata, "Author", "Creator", "Artist"),
        "last_modified_by": _get(metadata, "LastModifiedBy"),
        "created": _get(metadata, "CreateDate", "DateTimeOriginal"),
        "modified": _get(metadata, "ModifyDate", "FileModifyDate"),
        "software": _get(metadata, "Software", "Producer", "CreatorTool"),
        "company": _get(metadata, "Company"),
        "camera": " ".join(filter(None, [str(_get(metadata, "Make") or ""),
                                         str(_get(metadata, "Model") or "")])).strip() or None,
        "device_serial": _get(metadata, "SerialNumber", "BodySerialNumber"),
    }


def _parse_dt(value):
    """Timestamp exiftool -> datetime, None kalau tidak terbaca."""
    if not value:
        return None
    text = str(value).strip().split("+")[0].split("Z")[0].strip()
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text[:26], fmt)
        except ValueError:
            continue
    return None


def flag_suspicious_metadata(metadata: dict) -> list[str]:
    """Hal yang sering jadi 'jebakan' di soal kompetisi."""
    flags = []
    authorship = extract_document_authorship(metadata)

    # Dibandingkan sebagai WAKTU, bukan string: nilai dengan offset zona atau
    # format berbeda antar tipe file membuat perbandingan string salah diam-diam.
    created, modified = _parse_dt(authorship["created"]), _parse_dt(authorship["modified"])
    if created and modified and modified < created:
        flags.append(f"ModifyDate ({authorship['modified']}) lebih awal dari CreateDate "
                     f"({authorship['created']}) -- kemungkinan metadata dimanipulasi")

    software = str(authorship["software"] or "")
    hit = next((s for s in EDITING_SOFTWARE if s.lower() in software.lower()), None)
    if hit:
        flags.append(f"Berkas pernah diproses software editing: {software}")

    if extract_gps_coordinates(metadata) is None and str(
            _get(metadata, "MIMEType") or "").startswith("image"):
        flags.append("Tidak ada koordinat GPS -- bisa memang tidak pernah ada, "
                     "bisa juga sudah dihapus (cek apakah field EXIF lain masih utuh)")

    if _get(metadata, "Warning"):
        flags.append(f"exiftool memberi peringatan struktur berkas: {_get(metadata, 'Warning')}")
    return flags


def analyze_metadata(file_path, evidence: EvidenceLog | None = None) -> dict:
    if evidence is None:
        evidence = EvidenceLog()
    metadata = extract_all_metadata(file_path)
    if "error" in metadata:
        return metadata
    gps = extract_gps_coordinates(metadata)
    authorship = extract_document_authorship(metadata)
    flags = flag_suspicious_metadata(metadata)

    if gps:
        evidence.track("gps_coordinate", f"exiftool -GPSLatitude -GPSLongitude {file_path}",
                       f"{gps['latitude']}, {gps['longitude']}",
                       note=f"Koordinat GPS dari metadata berkas. {gps['maps_url']}")
    for field in ("author", "last_modified_by", "camera", "device_serial"):
        if authorship.get(field):
            evidence.track(f"metadata_{field}", f"exiftool -{field} {file_path}",
                           authorship[field])
    for flag in flags:
        evidence.track("metadata_anomaly", f"exiftool -a -G {file_path}", flag)

    return {"raw": metadata, "gps": gps, "authorship": authorship, "anomaly_flags": flags}
