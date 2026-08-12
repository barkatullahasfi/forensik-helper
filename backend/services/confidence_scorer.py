"""
Label HIGH/MEDIUM/LOW per temuan.

Gunanya bukan kosmetik laporan: memaksa membedakan apa yang benar-benar terlihat
di paket dari apa yang cuma disimpulkan dari metadata. Itu kebiasaan yang dilatih
tools ini.
"""

# Sumber bukti yang isinya benar-benar terbaca (bukan inferensi dari metadata).
DIRECT_SOURCES = {"http_payload", "dns_answer", "kerberos", "samr", "nbns", "dhcp",
                  "carved_file", "http_response", "threat_feed"}


def score_finding(finding: dict) -> str:
    """
    HIGH   : dikonfirmasi >=2 sumber independen DAN payload-nya terbaca
    MEDIUM : satu sumber, atau inferensi dari timing/metadata terenkripsi
    LOW    : satu sinyal lemah saja (mis. cuma bentuk nama domain)
    """
    sources = set(finding.get("evidence_sources", []))
    encrypted = finding.get("payload_encrypted", False)
    known_bad = finding.get("is_known_malicious", False)

    # Match ke threat feed itu konfirmasi eksternal: satu sumber pun sudah kuat.
    if known_bad and sources:
        return "HIGH"
    direct = sources & DIRECT_SOURCES
    if len(sources) >= 2 and direct and not encrypted:
        return "HIGH"
    if sources:
        return "MEDIUM"
    return "LOW"


def combine(*levels: str) -> str:
    """
    Gabungkan beberapa label jadi satu. Ambil yang TERENDAH, bukan tertinggi:
    kesimpulan tidak boleh lebih yakin daripada mata rantai terlemahnya.
    """
    order = ["LOW", "MEDIUM", "HIGH"]
    present = [l for l in levels if l in order]
    return min(present, key=order.index) if present else "LOW"


def explain(level: str) -> str:
    return {
        "HIGH": "Terlihat langsung di isi paket dan/atau cocok dengan threat feed",
        "MEDIUM": "Inferensi dari metadata/timing -- isi payload tidak terbaca",
        "LOW": "Satu sinyal lemah saja, perlu verifikasi manual",
    }.get(level, "")
