"""
Penggabung semua temuan jadi timeline + evidence index.

Output punya tiga lapisan, bukan cuma ringkasan:
1. key_events     -- event penting saja, untuk overview
2. all_sessions   -- SEMUA koneksi termasuk yang idle, supaya jumlah total sesi
                     bisa di-cross-check ("24 sesi TCP, 2 berisi HTTP lengkap")
3. evidence_index -- filter tshark persis per temuan, untuk Appendix Reproducibility
"""
from datetime import datetime, timezone

# Traffic legitimate yang memang berpola reguler / selalu ramai. TIDAK dipakai
# membuang temuan -- hanya menurunkan confidence. Whitelist yang menyembunyikan
# hasil adalah cara paling gampang melewatkan C2 yang menumpang domain terpercaya.
# Tinggal di sini (bukan di beacon_detector) supaya beacon_detector dan
# timeline_builder bisa memakainya tanpa import melingkar.
NOISE_DOMAIN_HINTS = (
    "microsoft.com", "msn.com", "bing.com", "windows.com", "windowsupdate.com",
    "msftconnecttest.com", "msftncsi.com", "office.com", "office365.com", "live.com",
    "google.com", "googleapis.com", "gstatic.com", "gvt1.com", "googleusercontent.com",
    "apple.com", "icloud.com", "mozilla.com", "mozilla.net", "adobedtm.com",
    "akamaitechnologies.com", "cloudflare.com", "cloudflareinsights.com", "ntp.org",
    # Layanan sertifikat/CRL. Selalu dihubungi lewat HTTP POLOS secara desain --
    # OCSP dan CRL tidak boleh memerlukan TLS, karena TLS-nya sendiri yang sedang
    # divalidasi. Tanpa ini, tiap sesi TLS yang sah memunculkan 'kandidat C2'.
    "pki.goog", "gvt2.com", "digicert.com", "verisign.com", "globalsign.com",
    "sectigo.com", "letsencrypt.org", "entrust.net", "godaddy.com", "amazontrust.com",
)


def is_noise(names: list[str]) -> bool:
    return any(hint in name for name in names for hint in NOISE_DOMAIN_HINTS)


def sort_key(event: dict) -> float:
    """
    Satu fungsi sort untuk SEMUA timeline di tools ini.

    Wajib dipakai: `key=lambda x: x.get("timestamp", "")` melempar TypeError
    begitu satu event punya datetime dan event lain punya "" atau None -- dan itu
    pasti terjadi di timeline gabungan yang menyatukan pcap (float epoch), disk
    (datetime), dan metadata file (string exiftool).

    Semua dinormalisasi ke epoch float; event tanpa waktu ditaruh di akhir.
    """
    ts = event.get("timestamp")
    if ts is None or ts == "":
        return float("inf")
    if isinstance(ts, bool):
        return float("inf")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).timestamp()
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(ts)[:19], fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return float(ts)
    except (TypeError, ValueError):
        return float("inf")


def to_utc(epoch: float | None) -> str | None:
    """Epoch -> string UTC yang bisa langsung ditempel ke laporan."""
    if epoch is None:
        return None
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class EvidenceLog:
    """
    Kumpulan {finding_type, wireshark_filter, result, note} per analisis.

    Objek per-analisis, bukan list global di level modul: dua analisis yang
    jalan bersamaan lewat BackgroundTasks akan saling mencampur temuan kalau
    state-nya dibagi.
    """

    def __init__(self):
        self.records: list[dict] = []

    def track(self, finding_type: str, wireshark_filter: str, result, note: str = "") -> dict:
        record = {
            "finding_type": finding_type,
            "wireshark_filter": wireshark_filter,
            "result": str(result),
            "note": note,
        }
        self.records.append(record)
        return record

    def __len__(self) -> int:
        return len(self.records)


def build_full_timeline(identity: dict, beacon_results: list, all_sessions: list,
                        evidence: EvidenceLog, capture_info: dict) -> dict:
    """Susun tiga lapisan output dari hasil modul-modul lain."""
    key_events = []

    first_seen = min((s["timestamp"] for s in all_sessions), default=None)
    if first_seen is not None:
        key_events.append({
            "timestamp": first_seen,
            "time_utc": to_utc(first_seen),
            "category": "capture_start",
            "description": f"Aktivitas pertama host {identity.get('ip')} dalam capture",
            "confidence": "HIGH",
        })

    key_events += http_destination_events(all_sessions, identity.get("ip", ""), evidence)

    for beacon in beacon_results:
        if not beacon["is_suspected_beacon"]:
            continue
        key_events.append({
            "timestamp": beacon["first_seen"],
            "time_utc": to_utc(beacon["first_seen"]),
            "category": "suspected_beacon",
            "description": (
                f"Pola koneksi reguler ke {beacon['label']} -- "
                f"{beacon['connection_count']} koneksi, interval rata-rata "
                f"{beacon['mean_interval_sec']:.1f} detik (CV {beacon['coefficient_variation']:.3f})"),
            "confidence": beacon["confidence"],
            "evidence_query": beacon["evidence_query"],
        })

    return {
        "capture_info": capture_info,
        "identity": identity,
        "key_events": sorted(key_events, key=sort_key),
        "all_sessions": sorted(all_sessions, key=sort_key),
        "session_summary": summarize_sessions(all_sessions),
        "evidence_index": evidence.records,
    }


def http_destination_events(all_sessions: list, internal_ip: str,
                            evidence: "EvidenceLog") -> list[dict]:
    """
    Destinasi yang benar-benar menerima/mengirim payload HTTP.

    Deteksi beaconing hanya menangkap C2 yang intervalnya TERATUR. C2 yang
    burst -- puluhan request dalam hitungan detik lalu diam -- punya CV tinggi
    dan lolos sepenuhnya. Kalau key_events cuma diisi hasil beacon, pcap dengan
    C2 HTTP yang jelas terlihat menghasilkan laporan kosong.

    Di sini payload-nya sendiri yang jadi sinyal: destinasi non-noise yang
    dikirimi HTTP request adalah kandidat teratas untuk diperiksa manual.
    """
    by_dest: dict[str, list[dict]] = {}
    for session in all_sessions:
        if session["has_payload"]:
            by_dest.setdefault(session["dst_ip"], []).append(session)

    events = []
    for dst_ip, group in by_dest.items():
        group.sort(key=sort_key)
        names = group[0]["resolved_names"]
        label = names[0] if names else dst_ip
        noise = is_noise(names)
        host_filter = f'http.host=="{label}"' if names else f"ip.addr=={dst_ip} && http"
        query = f"ip.src=={internal_ip} && {host_filter}"
        requests = [s["summary"] for s in group]
        events.append({
            "timestamp": group[0]["timestamp"],
            "time_utc": to_utc(group[0]["timestamp"]),
            "category": "http_traffic" if noise else "http_candidate_c2",
            "description": f"{len(group)} sesi HTTP ke {label}: " + "; ".join(requests[:3])
                           + (f" (+{len(requests) - 3} sesi lagi)" if len(requests) > 3 else ""),
            "destination": label,
            "confidence": "LOW" if noise else "MEDIUM",
            "evidence_query": query,
        })
        if not noise:
            evidence.track(
                "http_candidate_c2", query, label,
                note=f"{len(group)} sesi berisi HTTP request. Payload terlihat jelas "
                     f"(bukan TLS), jadi isi request bisa dibaca langsung untuk "
                     f"menentukan apakah ini C2. Request pertama: {requests[0]}")
    return events


def summarize_sessions(all_sessions: list) -> dict:
    """
    Angka yang selalu ditanyakan saat menyusun laporan: berapa total sesi, berapa
    yang benar-benar berisi payload. Sesi idle TIDAK dibuang -- dilaporkan apa
    adanya supaya jelas sudah dicek, bukan terlewat.
    """
    with_payload = sum(1 for s in all_sessions if s["has_payload"])
    inbound = sum(1 for s in all_sessions if s.get("direction") == "inbound")
    return {
        "total_sessions": len(all_sessions),
        "sessions_with_payload": with_payload,
        "sessions_idle": len(all_sessions) - with_payload,
        "sessions_outbound": len(all_sessions) - inbound,
        "sessions_inbound": inbound,
        "unique_destinations": len({s["dst_ip"] for s in all_sessions}),
    }
