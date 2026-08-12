"""
GeoIP + ASN lookup dari database MaxMind lokal (tanpa API call, tanpa rate limit).

Database GeoLite2 tidak bisa diunduh otomatis (butuh akun gratis MaxMind), jadi
modul ini harus tetap sopan saat databasenya belum ada: kembalikan status, jangan
menggagalkan analisis.
"""
import ipaddress
from pathlib import Path

from .. import config as settings

CITY_DB = "GeoLite2-City.mmdb"
ASN_DB = "GeoLite2-ASN.mmdb"


def db_path(name: str) -> Path:
    return settings.STORAGE / "geoip" / name


def available() -> bool:
    return db_path(CITY_DB).exists() or db_path(ASN_DB).exists()


def status() -> dict:
    return {
        "available": available(),
        "city_db": str(db_path(CITY_DB)) if db_path(CITY_DB).exists() else None,
        "asn_db": str(db_path(ASN_DB)) if db_path(ASN_DB).exists() else None,
        "hint": None if available() else
                "Daftar gratis di maxmind.com/en/geolite2/signup, unduh "
                f"GeoLite2-City.mmdb dan GeoLite2-ASN.mmdb ke {db_path('')}",
    }


def is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_multicast
                or addr.is_link_local or addr.is_reserved)


def enrich_ips(ips: list[str]) -> list[dict]:
    """
    Lookup batch. Reader dibuka SEKALI untuk semua IP -- membuka/menutup file
    mmdb per IP adalah cara paling gampang membuat modul ini lambat.
    """
    external = sorted({ip for ip in ips if ip and is_external(ip)})
    if not external:
        return []
    if not available():
        return [{"ip": ip, "error": "database GeoLite2 belum tersedia"} for ip in external]

    try:
        import geoip2.database
        import geoip2.errors
    except ImportError:
        return [{"ip": ip, "error": "paket geoip2 belum terpasang"} for ip in external]

    city_reader = (geoip2.database.Reader(str(db_path(CITY_DB)))
                   if db_path(CITY_DB).exists() else None)
    asn_reader = (geoip2.database.Reader(str(db_path(ASN_DB)))
                  if db_path(ASN_DB).exists() else None)
    results = []
    try:
        for ip in external:
            entry = {"ip": ip, "country": None, "city": None,
                     "latitude": None, "longitude": None, "asn": None, "organization": None}
            if city_reader:
                try:
                    city = city_reader.city(ip)
                    entry.update(country=city.country.name, city=city.city.name,
                                 latitude=city.location.latitude,
                                 longitude=city.location.longitude)
                except geoip2.errors.AddressNotFoundError:
                    pass
            if asn_reader:
                try:
                    asn = asn_reader.asn(ip)
                    entry.update(asn=asn.autonomous_system_number,
                                 organization=asn.autonomous_system_organization)
                except geoip2.errors.AddressNotFoundError:
                    pass
            results.append(entry)
    finally:
        for reader in (city_reader, asn_reader):
            if reader:
                reader.close()
    return results
