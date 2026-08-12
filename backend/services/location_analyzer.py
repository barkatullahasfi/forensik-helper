"""
Gabungan dua sumber lokasi yang MAKNANYA BERBEDA.

- GeoIP  = perkiraan lokasi server/ISP. Sering tidak akurat: VPN, proxy, CDN,
           dan blok IP yang didaftarkan di negara lain.
- GPS    = lokasi fisik kamera saat foto diambil. Jauh lebih akurat, TAPI mudah
           dihapus atau dipalsukan.

Keduanya tidak boleh dicampur sebagai "lokasi pasti". Modul ini menggabungkan
titiknya tapi mempertahankan label sumber dan confidence-nya.
"""
from .timeline_builder import sort_key


def build_location_timeline(geoip_results: list[dict], gps_results: list[dict]) -> list[dict]:
    combined = []
    for entry in geoip_results or []:
        if entry.get("latitude") is None:
            continue
        combined.append({
            "source": "GeoIP (network)",
            "confidence": "LOW",
            "label": entry.get("ip"),
            "latitude": entry["latitude"], "longitude": entry["longitude"],
            "detail": ", ".join(filter(None, [entry.get("city"), entry.get("country"),
                                              entry.get("organization")])),
            "timestamp": entry.get("timestamp"),
            "caveat": "Lokasi perkiraan server/ISP -- bisa VPN/proxy/CDN, "
                      "bukan lokasi orang",
        })
    for entry in gps_results or []:
        if entry.get("latitude") is None:
            continue
        combined.append({
            "source": "GPS (metadata berkas)",
            "confidence": "HIGH",
            "label": entry.get("filename") or entry.get("label"),
            "latitude": entry["latitude"], "longitude": entry["longitude"],
            "detail": entry.get("maps_url"),
            "timestamp": entry.get("timestamp"),
            "caveat": "Lokasi fisik kamera saat pengambilan -- akurat kalau asli, "
                      "tapi metadata bisa dipalsukan",
        })
    return sorted(combined, key=sort_key)


def generate_map_data(locations: list[dict]) -> list[dict]:
    """Format siap render (Leaflet/Google Maps)."""
    return [{"lat": l["latitude"], "lon": l["longitude"], "label": l["label"],
             "source": l["source"], "confidence": l["confidence"]}
            for l in locations if l.get("latitude") is not None]


def summarize(locations: list[dict]) -> dict:
    gps = [l for l in locations if l["source"].startswith("GPS")]
    geoip = [l for l in locations if l["source"].startswith("GeoIP")]
    return {
        "total_points": len(locations),
        "gps_points": len(gps),
        "geoip_points": len(geoip),
        "countries": sorted({l["detail"].split(", ")[-1] for l in geoip if l.get("detail")}),
        "note": "GPS dan GeoIP menjawab pertanyaan berbeda. Jangan simpulkan "
                "'pelaku berada di negara X' dari GeoIP saja.",
    }
