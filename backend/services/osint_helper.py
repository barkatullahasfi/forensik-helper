"""
Alat bantu terstruktur untuk investigasi peserta/pelaku.

BUKAN otomasi OSINT: tidak scraping media sosial, tidak crawling web. Modul ini
MENYUSUN apa yang sudah ditemukan modul lain dan menyiapkan query yang harus kamu
cek manual di browser.
"""


def structure_osint_query(username: str, context: dict | None = None) -> dict:
    """
    Susun query yang PERLU dicek manual, berdasarkan data yang sudah ada.

    Query di sini tidak dieksekusi oleh tools -- scraping otomatis melanggar ToS
    banyak platform dan di luar scope tools pribadi ini.
    """
    context = context or {}
    domain = context.get("ad_domain") or ""
    org = context.get("organization_hint") or ""
    full_name = context.get("full_name") or ""

    queries = [f'"{username}" site:linkedin.com', f'"{username}" site:github.com']
    if org:
        queries.append(f'"{username}" "{org}"')
    if domain:
        queries.append(f"{username}@{domain}")
        queries.append(f'site:{domain} "{username}"')
    if full_name:
        queries += [f'"{full_name}" site:linkedin.com', f'"{full_name}" {org}'.strip()]
    return {
        "username": username,
        "full_name": full_name or None,
        "suggested_searches": [q for q in queries if q],
        "note": "Query di atas perlu dicek MANUAL di browser. Tools ini tidak "
                "melakukan pencarian atau scraping otomatis.",
    }


def build_participant_profile(identity: dict, result: dict) -> dict:
    """
    Satukan semua yang sudah diketahui tentang satu host/orang jadi satu profil
    untuk bagian 'Analisa Peserta/Pelaku' di laporan.
    """
    hostnames = identity.get("hostname") or []
    ad_domain = next((h.split(".", 1)[1] for h in hostnames if "." in h), "")

    return {
        "identity": identity,
        "network_footprint": {
            "sessions": result.get("session_summary", {}),
            "top_destinations": [b["label"] for b in result.get("beacons", [])[:10]],
            "suspicious_destinations": [
                e["destination"] for e in result.get("key_events", [])
                if e.get("category") == "http_candidate_c2"],
        },
        "known_locations": result.get("locations", []),
        "device_hints": {
            "mac_vendor_prefix": (identity.get("mac") or "")[:8] or None,
            "hostnames": hostnames,
        },
        "osint_starting_points": structure_osint_query(
            identity.get("username") or "",
            {"ad_domain": ad_domain, "full_name": identity.get("full_name")}
        ) if identity.get("username") else None,
        "manual_verification_required": True,   # selalu: profil sosial tidak
                                                # pernah bisa dipastikan dari pcap
        "note": "Profil ini disusun dari bukti teknis di dalam evidence. "
                "Menghubungkannya ke orang sungguhan butuh verifikasi manual "
                "di luar tools ini.",
    }
