"""
Deteksi anomali Kerberos: downgrade enkripsi, TGT berumur janggal, dan pola
request service ticket yang menyerupai Kerberoasting.

Semua berbasis field yang memang di-decode tshark; tidak ada tebakan kriptografi.
"""
from collections import Counter

from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, to_utc

# RFC 3961 etype. RC4 (23) bisa di-crack offline; itu yang dicari Kerberoasting.
ETYPE_NAMES = {1: "des-cbc-crc", 3: "des-cbc-md5", 17: "aes128-cts-hmac-sha1-96",
               18: "aes256-cts-hmac-sha1-96", 23: "rc4-hmac", 24: "rc4-hmac-exp"}
WEAK_ETYPES = {1, 3, 23, 24}

MSG_TYPES = {"10": "AS-REQ", "11": "AS-REP", "12": "TGS-REQ", "13": "TGS-REP", "30": "KRB-ERROR"}


def detect_kerberos_anomalies(pcap_path, internal_ip: str | None = None,
                              evidence: EvidenceLog | None = None) -> dict:
    if evidence is None:
        evidence = EvidenceLog()
    scope = f" && ip.src=={internal_ip}" if internal_ip else ""

    findings = []
    findings += _detect_weak_etype(pcap_path, scope, internal_ip, evidence)
    findings += _detect_kerberoasting_spray(pcap_path, scope, internal_ip, evidence)

    return {"findings": findings, "summary": _message_mix(pcap_path, scope)}


def _detect_weak_etype(pcap_path, scope, internal_ip, evidence) -> list[dict]:
    """
    Request TGS dengan etype lemah (RC4) padahal AES tersedia = indikasi klasik
    Kerberoasting: penyerang sengaja meminta tiket yang bisa di-brute force offline.
    """
    rows = run_tshark_fields(
        pcap_path, f"kerberos.msg_type==12{scope}",
        ["frame.number", "frame.time_epoch", "kerberos.etype", "kerberos.SNameString"])
    findings = []
    for row in rows:
        etypes = {int(e) for e in row["kerberos.etype"].split(",") if e.strip().isdigit()}
        if not etypes or not etypes & WEAK_ETYPES:
            continue
        # Klien yang menawarkan RC4 BERSAMA AES itu normal (daftar kemampuan).
        # Yang mencurigakan: RC4 saja, tanpa AES sama sekali.
        if etypes & {17, 18}:
            continue
        service = row["kerberos.SNameString"].replace(",", "/")
        query = f"kerberos.msg_type==12 && kerberos.etype==23"
        findings.append({
            "type": "kerberos_rc4_downgrade",
            "frame_number": _int(row["frame.number"]),
            "time_utc": to_utc(_float(row["frame.time_epoch"])),
            "service": service,
            "etypes_offered": sorted(ETYPE_NAMES.get(e, str(e)) for e in etypes),
            "confidence": "MEDIUM",
            "note": "TGS-REQ hanya menawarkan enkripsi lemah tanpa AES -- pola "
                    "Kerberoasting. Bisa juga klien/servis lawas, cek konteksnya",
            "evidence_query": query,
        })
        evidence.track("kerberos_rc4_downgrade", query, service, note=findings[-1]["note"])
    return findings


def _detect_kerberoasting_spray(pcap_path, scope, internal_ip, evidence,
                                threshold: int = 5, window_sec: int = 60) -> list[dict]:
    """Banyak TGS-REQ ke service account berbeda dalam waktu singkat."""
    rows = run_tshark_fields(pcap_path, f"kerberos.msg_type==12{scope}",
                             ["frame.time_epoch", "kerberos.SNameString"])
    events = []
    for row in rows:
        ts = _float(row["frame.time_epoch"])
        name = row["kerberos.SNameString"].replace(",", "/")
        if ts is not None and name:
            events.append((ts, name))
    events.sort()

    findings, start = [], 0
    for end in range(len(events)):
        while events[end][0] - events[start][0] > window_sec:
            start += 1
        services = {name for _, name in events[start:end + 1]}
        if len(services) >= threshold:
            query = f"kerberos.msg_type==12{scope}"
            findings.append({
                "type": "kerberoasting_spray",
                "window_start_utc": to_utc(events[start][0]),
                "window_end_utc": to_utc(events[end][0]),
                "distinct_services": sorted(services),
                "service_count": len(services),
                "confidence": "MEDIUM",
                "note": f"{len(services)} service berbeda diminta tiketnya dalam "
                        f"{window_sec} detik. Login normal tidak seperti ini, tapi "
                        "startup aplikasi enterprise kadang mirip -- verifikasi manual",
                "evidence_query": query,
            })
            evidence.track("kerberoasting_spray", query,
                           f"{len(services)} service dalam {window_sec} detik",
                           note=findings[-1]["note"])
            break   # satu temuan cukup; sisanya window yang tumpang tindih
    return findings


def _message_mix(pcap_path, scope) -> dict:
    """Ringkasan jenis pesan Kerberos -- konteks untuk menilai temuan di atas."""
    rows = run_tshark_fields(pcap_path, f"kerberos{scope}", ["kerberos.msg_type"])
    counts = Counter()
    for row in rows:
        for value in row["kerberos.msg_type"].split(","):
            if value.strip():
                counts[MSG_TYPES.get(value.strip(), value.strip())] += 1
    return dict(counts)


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
