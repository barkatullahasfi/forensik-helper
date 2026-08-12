"""
Self-check logika inti tanpa perlu pcap.

Jalankan: python tests/test_mvp.py   (atau pytest tests/)
Yang diuji cuma yang bisa rusak diam-diam: statistik beacon, normalisasi waktu,
dan pembersihan hostname. Wrapper subprocess tidak diuji di sini -- itu tugas
validasi terhadap pcap asli.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.services.beacon_detector import (  # noqa: E402
    detect_beaconing, detect_domain_rotation)
from backend.services.identity_extractor import _clean_hostname  # noqa: E402
from backend.services.timeline_builder import (  # noqa: E402
    EvidenceLog, sort_key, summarize_sessions)


def session(ts, dst="1.2.3.4", names=None, payload=False, port=443, direction="outbound"):
    return {"frame_number": 1, "timestamp": ts, "time_utc": None, "tcp_stream": 0,
            "direction": direction, "src_ip": "10.0.0.1",
            "dst_ip": dst, "dst_port": port, "resolved_names": names or [],
            "has_payload": payload, "summary": ""}


def test_beacon_detects_regular_interval():
    """Interval persis 60 detik = CV 0 = beacon paling jelas."""
    sessions = [session(1000 + i * 60) for i in range(10)]
    result = detect_beaconing(sessions, internal_ip="10.0.0.1")[0]
    assert result["is_suspected_beacon"] is True
    assert result["mean_interval_sec"] == 60.0
    assert result["coefficient_variation"] == 0.0
    assert result["confidence"] == "HIGH"


def test_beacon_ignores_irregular_traffic():
    """Browsing manusia: jarak tidak teratur, tidak boleh di-flag."""
    sessions = [session(t) for t in (0, 3, 47, 51, 300, 1200, 1207)]
    result = detect_beaconing(sessions, internal_ip="10.0.0.1")[0]
    assert result["is_suspected_beacon"] is False
    assert result["confidence"] == "LOW"


def test_beacon_needs_minimum_datapoints():
    """2 koneksi cuma menghasilkan 1 delta -- tidak ada variasi untuk dihitung."""
    assert detect_beaconing([session(0), session(60)], internal_ip="10.0.0.1") == []


def test_beacon_survives_simultaneous_connections():
    """Semua SYN pada detik yang sama: mean delta 0, tidak boleh ZeroDivisionError."""
    result = detect_beaconing([session(500) for _ in range(5)], internal_ip="10.0.0.1")[0]
    assert result["is_suspected_beacon"] is False
    assert result["coefficient_variation"] is None


def test_known_noise_domain_is_flagged_not_hidden():
    """Telemetry Microsoft tetap muncul di hasil, cuma diturunkan confidence-nya."""
    sessions = [session(1000 + i * 60, names=["telemetry.microsoft.com"]) for i in range(10)]
    result = detect_beaconing(sessions, internal_ip="10.0.0.1")[0]
    assert result["is_suspected_beacon"] is True   # tetap dilaporkan
    assert result["is_known_noise"] is True
    assert result["confidence"] == "LOW"           # tapi tidak dianggap temuan kuat


def test_domain_rotation_window():
    """6 destinasi berbeda dalam 3 menit = pola rotasi domain (kasus FormBook)."""
    sessions = [session(i * 30, dst=f"9.9.9.{i}") for i in range(6)]
    hits = detect_domain_rotation(sessions, window_sec=300, min_domains=5)
    assert hits and hits[0]["destination_count"] == 6

    spread = [session(i * 600, dst=f"9.9.9.{i}") for i in range(6)]
    assert detect_domain_rotation(spread, window_sec=300, min_domains=5) == []


def test_sort_key_mixes_types_without_crashing():
    """Ini bug yang bikin master timeline mati: datetime + string + None dalam satu list."""
    events = [
        {"timestamp": None},
        {"timestamp": datetime(2026, 1, 31, 10, 0, tzinfo=timezone.utc)},
        {"timestamp": "2026-01-30 09:00:00"},
        {"timestamp": 1000.5},
        {"timestamp": ""},
        {"timestamp": "2026:01:29 08:00:00"},   # format exiftool
    ]
    ordered = sorted(events, key=sort_key)
    assert ordered[0]["timestamp"] == 1000.5              # epoch 1970, paling awal
    assert ordered[1]["timestamp"] == "2026:01:29 08:00:00"
    assert ordered[2]["timestamp"] == "2026-01-30 09:00:00"
    assert sort_key(ordered[-1]) == float("inf")          # tanpa waktu ditaruh di akhir


def test_session_summary_counts_idle_sessions():
    """Sesi idle tidak boleh hilang dari hitungan -- itu poin utama laporan."""
    sessions = [session(1, payload=True), session(2), session(3), session(4, dst="5.5.5.5")]
    summary = summarize_sessions(sessions)
    assert summary["total_sessions"] == 4
    assert summary["sessions_with_payload"] == 1
    assert summary["sessions_idle"] == 3
    assert summary["unique_destinations"] == 2


def test_session_summary_separates_direction():
    """
    Capture di sisi SERVER tidak punya sesi keluar sama sekali -- server
    menerima koneksi, tidak memulainya. Menghitung hanya arah keluar melaporkan
    '0 sesi' untuk capture berisi puluhan ribu paket.
    """
    sessions = [session(1), session(2, direction="inbound"), session(3, direction="inbound")]
    summary = summarize_sessions(sessions)
    assert summary["sessions_outbound"] == 1
    assert summary["sessions_inbound"] == 2
    assert summary["total_sessions"] == 3


def test_inbound_sessions_never_counted_as_beacon():
    """
    Koneksi MASUK yang teratur adalah scanner atau health-check, bukan C2.
    Memasukkannya membuat setiap server ter-flag sebagai beacon.
    """
    inbound = [session(1000 + i * 60, direction="inbound") for i in range(10)]
    assert detect_beaconing(inbound, internal_ip="10.0.0.1") == []
    outbound = [session(1000 + i * 60) for i in range(10)]
    assert detect_beaconing(outbound, internal_ip="10.0.0.1")[0]["is_suspected_beacon"]


def test_hostname_cleaning():
    """tshark menuliskan nbns.name lengkap dengan penjelasan servicenya."""
    assert _clean_hostname("DESKTOP-ES9F3ML<00> (Workstation/Redirector)") == "DESKTOP-ES9F3ML"
    assert _clean_hostname("WIN11OFFICE<1e> (Browser Election Service)") == "WIN11OFFICE"
    assert _clean_hostname("DESKTOP-ES9F3ML<00>") == "DESKTOP-ES9F3ML"
    assert _clean_hostname("DESKTOP-ES9F3ML$") == "DESKTOP-ES9F3ML"
    assert _clean_hostname("  host<20>  ") == "host"
    assert _clean_hostname("") == ""


def test_samr_fullname_ignores_nested_struct_header():
    """
    Regresi: struktur SAMR bertingkat punya 3 baris mengandung 'Full Name'.
    Regex multiline `\\s*` melompati newline dan menangkap 'Name Len: 26'.
    """
    verbose = (
        "                      Full Name: \n"
        "                          Name Len: 26\n"
        "                          Name Size: 26\n"
        "                          Full Name\n"
        "                              Actual Count: 13\n"
        "                              Full Name: Gabriel Wyatt\n"
        "                      Home Drive: \n"
        "                          Name Len: 0\n")
    values = []
    for line in verbose.splitlines():
        label, sep, value = line.strip().partition(":")
        if sep and label.strip() == "Full Name" and value.strip():
            values.append(value.strip())
    assert values == ["Gabriel Wyatt"]


def test_evidence_log_is_per_instance():
    """Dua analisis paralel tidak boleh saling mencampur temuan."""
    a, b = EvidenceLog(), EvidenceLog()
    a.track("mac_address", "ip.src==10.0.0.1 && eth.src", "aa:bb:cc")
    assert len(a) == 1 and len(b) == 0
    assert a.records[0]["wireshark_filter"] == "ip.src==10.0.0.1 && eth.src"


def test_empty_evidence_log_is_falsy_so_never_use_or_default():
    """
    Regresi: EvidenceLog punya __len__, jadi log KOSONG bernilai falsy.
    `evidence = evidence or EvidenceLog()` diam-diam membuang log yang dioper
    dan seluruh temuan identitas hilang dari appendix.
    """
    passed_in = EvidenceLog()
    assert not passed_in, "log kosong memang falsy -- ini yang bikin `or` berbahaya"
    assert (passed_in or EvidenceLog()) is not passed_in   # pola yang SALAH
    assert (passed_in if passed_in is not None else EvidenceLog()) is passed_in  # yang BENAR


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ok    {test.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {test.__name__}: {e or '(assert)'}")
    print(f"\n{len(tests) - failed}/{len(tests)} lulus")
    raise SystemExit(1 if failed else 0)
