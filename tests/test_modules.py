"""
Self-check modul lanjutan. Jalankan: python tests/test_modules.py

Fokus pada logika yang bisa rusak diam-diam: parsing feed, ambang skor, validasi
signature, klasifikasi outcome. Wrapper subprocess tidak diuji di sini.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.services import (confidence_scorer, cross_evidence_correlator,  # noqa: E402
                              dga_detector, mitre_mapper, owasp_detector,
                              steganography_detector, threat_feed)
from backend.services.identity_extractor import _clean_hostname  # noqa: E402


# ---------- DGA ----------

def test_dga_normalized_entropy_reachable_for_short_domains():
    """
    Bug yang diperbaiki: entropy MENTAH maksimum = log2(panjang), jadi domain
    9 huruf tidak pernah bisa melewati ambang 3.3 dan kriterianya mati.
    """
    assert dga_detector.calculate_entropy("taibeinan") < 3.3      # mustahil lolos
    assert 0.0 <= dga_detector.normalized_entropy("taibeinan") <= 1.0
    assert dga_detector.normalized_entropy("aaaaaaaa") < 0.2      # sangat teratur
    assert dga_detector.normalized_entropy("x7fq2mzk") > 0.9      # sangat acak


def test_dga_scores_label_not_www():
    result = dga_detector.score_domain("www.google.com")
    assert result["label_scored"] == "google"
    assert dga_detector.score_domain("arch.filemegahab4.sbs")["label_scored"] == "filemegahab4"


def test_dga_ranks_c2_above_legitimate():
    domains = ["taibeinan.cc", "21207628.shop", "grinswakebthu.info", "www.google.com"]
    scores = {r["domain"]: r["dga_suspicion_score"]
              for r in dga_detector.detect_dga_pattern(domains)}
    assert all(scores[d] > scores["www.google.com"] for d in domains if d != "www.google.com")


# ---------- Threat feed ----------

def test_urlhaus_parsed_as_hostname_not_url():
    """Kolom 2 URLhaus adalah URL LENGKAP; tanpa parsing, lookup selalu False."""
    with tempfile.TemporaryDirectory() as tmp:
        feed = Path(tmp) / "urlhaus.csv"
        feed.write_text('# comment\n"1","2026-01-01","http://evil.test/x.exe","online"\n',
                        encoding="utf-8")
        hosts = threat_feed.load_urlhaus_hosts(feed)
    assert hosts == {"evil.test"}, f"harusnya hostname, dapat {hosts}"


def test_threatfox_strips_port_from_ip():
    """ioc_value ThreatFox untuk IP berformat '1.2.3.4:443' -- port wajib dibuang."""
    with tempfile.TemporaryDirectory() as tmp:
        feed = Path(tmp) / "threatfox.csv"
        feed.write_text(
            '# comment\n"2026-01-01", "1", "1.2.3.4:443", "ip:port", "botnet_cc"\n'
            '"2026-01-01", "2", "bad.test", "domain", "botnet_cc"\n'
            '"2026-01-01", "3", "d41d8cd98f00b204e9800998ecf8427e", "md5_hash", "payload"\n',
            encoding="utf-8")
        hosts, hashes = threat_feed.load_threatfox_iocs(feed)
    assert "1.2.3.4" in hosts, f"port tidak dibuang: {hosts}"
    assert "1.2.3.4:443" not in hosts
    assert "bad.test" in hosts
    assert "d41d8cd98f00b204e9800998ecf8427e" in hashes


def test_missing_feed_file_is_not_a_crash():
    assert threat_feed.load_urlhaus_hosts(Path("tidak/ada.csv")) == set()


# ---------- OWASP ----------

def test_xss_not_reflected_without_echo():
    """Bug yang diperbaiki: mengembalikan 'reflected' untuk SEMUA 200 = FP pabrikan."""
    payload = "<script>alert(1)</script>"
    no_echo = {"status_code": 200, "body": "halaman normal tanpa payload"}
    echoed = {"status_code": 200, "body": f"hasil pencarian: {payload}"}
    category = "A03:2021 - Injection (XSS)"
    assert owasp_detector.classify_outcome(category, payload, no_echo) == "no_effect"
    assert owasp_detector.classify_outcome(category, payload, echoed) == "reflected"


def test_outcome_classification():
    c = "A03:2021 - Injection (SQLi)"
    assert owasp_detector.classify_outcome(c, "x", None) == "no_response"
    assert owasp_detector.classify_outcome(c, "x", {"status_code": 403}) == "blocked"
    assert owasp_detector.classify_outcome(c, "x", {"status_code": 500}) == "error"
    assert owasp_detector.classify_outcome(
        c, "x", {"status_code": 200, "body": "root:x:0:0:root"}) == "leaked"


def test_confidence_follows_outcome():
    assert owasp_detector._score_confidence("leaked") == "HIGH"
    assert owasp_detector._score_confidence("blocked") == "MEDIUM"


def test_sqli_patterns_match_real_payloads():
    """Payload asli dari WebInvestigation.pcap."""
    from urllib.parse import unquote
    import re
    payloads = ["' or 1=1; -- -", "book' AND 7459=3526 AND 'PyAo'='PyAo",
                "1 UNION ALL SELECT 1,NULL,NULL", "1 AND SLEEP(5)"]
    for payload in payloads:
        decoded = unquote(payload)
        assert any(re.search(p, decoded, re.IGNORECASE) for p in owasp_detector.SQLI_PATTERNS), \
            f"tidak terdeteksi: {payload}"


def test_benign_query_not_flagged_as_sqli():
    import re
    for benign in ["/search.php?q=buku+sejarah", "/produk?id=42", "/artikel/cara-select-data"]:
        assert not any(re.search(p, benign, re.IGNORECASE) for p in owasp_detector.SQLI_PATTERNS), \
            f"false positive: {benign}"


# ---------- Steganografi ----------

def test_mz_alone_is_not_a_pe_signature():
    """
    Bug yang diperbaiki: 'MZ' cuma 2 byte, muncul acak ~sekali per 65 KB.
    Satu JPEG 3,5 MB menghasilkan puluhan 'PE executable' palsu.
    """
    with tempfile.TemporaryDirectory() as tmp:
        noise = Path(tmp) / "noise.bin"
        noise.write_bytes(b"\x00" * 100 + b"MZ" + b"\x00" * 100)   # MZ tanpa header PE
        assert steganography_detector.scan_embedded_signatures(noise) == []


def test_real_pe_is_detected():
    """Validator tidak boleh menolak PE sungguhan."""
    data = bytearray(b"\x11" * 0x200)
    data[0x100:0x102] = b"MZ"
    data[0x13C:0x140] = (0x80).to_bytes(4, "little")   # e_lfanew
    data[0x180:0x184] = b"PE\x00\x00"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "embedded.bin"
        path.write_bytes(bytes(data))
        found = steganography_detector.scan_embedded_signatures(path)
    assert any(f["type"] == "DOS/PE executable" and f["offset"] == 0x100 for f in found)


def test_appended_zip_detected():
    """JPEG utuh + ZIP ditempel di belakang -- kasus stego paling umum."""
    zip_blob = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"secret.txt" + b"\x00" * 20
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "stego.jpg"
        path.write_bytes(b"\xff\xd8\xff" + b"A" * 500 + b"\xff\xd9" + zip_blob)
        assert any(f["type"] == "ZIP archive"
                   for f in steganography_detector.scan_embedded_signatures(path))
        trailing = steganography_detector.check_trailing_data(path)
    assert trailing and trailing["marker"] == "JPEG EOI"
    assert trailing["trailing_bytes"] == len(zip_blob)


def test_boring_namespace_urls_filtered():
    """
    String di berkas nyata dipisah null byte, jadi URL namespace dan URL asli
    jadi entry terpisah -- itu yang membuat filter ini bisa memilih.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "img.jpg"
        path.write_bytes(b"http://ns.adobe.com/xap/1.0/\x00\x00"
                         b"http://www.w3.org/1999/02/22-rdf-syntax-ns#\x00\x00"
                         b"https://evil-c2.test/beacon\x00")
        strings = steganography_detector._interesting_strings(path)
    assert any("evil-c2.test" in s for s in strings), f"URL asli hilang: {strings}"
    assert not any("ns.adobe.com" in s or "w3.org" in s for s in strings), \
        f"namespace boilerplate lolos: {strings}"


# ---------- Confidence & MITRE ----------

def test_confidence_takes_weakest_link():
    assert confidence_scorer.combine("HIGH", "LOW", "MEDIUM") == "LOW"
    assert confidence_scorer.combine("HIGH", "HIGH") == "HIGH"


def test_confidence_scoring():
    assert confidence_scorer.score_finding({}) == "LOW"
    assert confidence_scorer.score_finding(
        {"evidence_sources": ["dns_answer"]}) == "MEDIUM"
    assert confidence_scorer.score_finding(
        {"evidence_sources": ["dns_answer", "http_payload"]}) == "HIGH"
    assert confidence_scorer.score_finding(
        {"evidence_sources": ["dns_answer", "http_payload"],
         "payload_encrypted": True}) == "MEDIUM"


def test_mitre_maps_only_present_findings():
    result = mitre_mapper.map_findings_to_mitre(["http_candidate_c2", "full_name"])
    techniques = {r["technique"] for r in result}
    assert techniques == {"T1071.001", "T1087.002"}
    assert mitre_mapper.map_findings_to_mitre([]) == []


# ---------- Korelasi lintas evidence ----------

def test_network_memory_correlation():
    pcap = {"all_sessions": [{"dst_ip": "5.5.5.5"}], "threat_feed_hits": []}
    memory = {"connections": [{"ForeignAddr": "5.5.5.5", "Owner": "evil.exe", "PID": 1337}]}
    correlations = cross_evidence_correlator.correlate_network_and_memory(pcap, memory)
    assert len(correlations) == 1
    assert correlations[0]["process_name"] == "evil.exe"
    assert correlations[0]["confidence"] == "HIGH"


def test_correlation_uses_all_capture_ips_not_just_target_sessions():
    """
    Bug yang diperbaiki: korelasi hanya membaca `all_sessions`, yang isinya lalu
    lintas KELUAR dari satu host target saja. Di evidence pack, RAM dump lazimnya
    diambil dari KORBAN sementara target pcap tertebak ke penyerang -- akibatnya
    korelasi selalu nol padahal kedua evidence jelas satu mesin.
    """
    pcap = {"all_ips": ["10.0.2.15", "10.0.2.4", "20.42.73.29"],
            "all_sessions": [], "threat_feed_hits": []}
    memory = {"connections": [
        {"LocalAddr": "10.0.2.15", "ForeignAddr": "10.0.2.4",
         "Owner": "w3wp.exe", "PID": 4332, "ForeignPort": 4443}]}
    result = cross_evidence_correlator.correlate_network_and_memory(pcap, memory)
    types = {c["type"] for c in result}
    assert "dump_host_identified" in types, "host asal dump harus dikenali dari LocalAddr"
    assert "network_process_match" in types
    assert all(c["confidence"] == "HIGH" for c in result)


def test_dump_host_reported_once_not_per_connection():
    """72 koneksi dari host yang sama tidak boleh jadi 72 catatan identik."""
    pcap = {"all_ips": ["10.0.2.15"], "all_sessions": [], "threat_feed_hits": []}
    memory = {"connections": [{"LocalAddr": "10.0.2.15", "ForeignAddr": "8.8.8.8"}
                              for _ in range(20)]}
    result = cross_evidence_correlator.correlate_network_and_memory(pcap, memory)
    assert sum(1 for c in result if c["type"] == "dump_host_identified") == 1


def test_target_ip_heuristic_prefers_victim_over_attacker():
    """
    Menghitung ip.src saja memilih pengirim terbanyak, yang di capture serangan
    justru PENYERANG. Terbukti di capture uji: 10.0.2.4 mengirim 4166 paket,
    10.0.2.15 menerima 4248 -- dan RAM dump berasal dari 10.0.2.15.
    """
    from unittest.mock import patch
    from backend.services import pcap_parser
    # Angka persis dari capture uji: penyerang 4166 kirim / 1841 terima,
    # korban 2012 kirim / 4248 terima.
    rows = ([{"ip.src": "10.0.2.4", "ip.dst": "10.0.2.15"}] * 4166
            + [{"ip.src": "10.0.2.15", "ip.dst": "10.0.2.4"}] * 1841
            + [{"ip.src": "10.0.2.15", "ip.dst": "8.8.8.8"}] * 171
            + [{"ip.src": "8.8.8.8", "ip.dst": "10.0.2.15"}] * 82)
    with patch.object(pcap_parser, "run_tshark_fields", lambda *a, **k: rows):
        ranking = pcap_parser.rank_internal_hosts("dummy.pcap")
        assert ranking[0]["ip"] == "10.0.2.15", f"harusnya korban, dapat {ranking[0]}"
        assert ranking[1]["ip"] == "10.0.2.4"
        # Heuristik lama (ip.src terbanyak) akan memilih penyerang di sini.
        assert max(ranking, key=lambda h: h["packets_sent"])["ip"] == "10.0.2.4"
        assert pcap_parser.guess_target_ip("dummy.pcap") == "10.0.2.15"
        # IP publik tetap dikembalikan -- korelasi lintas evidence memerlukan
        # daftar IP yang lengkap. Yang diatur hanya URUTANNYA: privat lebih dulu,
        # sehingga pemilihan target tidak pernah jatuh ke server eksternal.
        assert "8.8.8.8" in {h["ip"] for h in ranking}
        assert all(h["is_private"] for h in ranking[:2])


def test_ranking_falls_back_to_public_when_no_private_host():
    """
    Capture di sisi SERVER tidak punya satu pun alamat privat. Menolak pcap
    seperti itu berarti tools menampik justru skenario yang modul OWASP-nya
    dibuat untuk menanganinya.
    """
    from unittest.mock import patch
    from backend.services import pcap_parser
    # Butuh host ketiga: dalam pertukaran dua host, total paket keduanya SELALU
    # seri karena tiap paket menambah satu ke pengirim dan satu ke penerima.
    # Capture aslinya pun begitu -- server unggul justru lewat lalu lintas ke
    # host lain (170.40.150.126).
    rows = ([{"ip.src": "111.224.250.131", "ip.dst": "73.124.22.98"}] * 44
            + [{"ip.src": "73.124.22.98", "ip.dst": "111.224.250.131"}] * 45
            + [{"ip.src": "73.124.22.98", "ip.dst": "170.40.150.126"}] * 10)
    with patch.object(pcap_parser, "run_tshark_fields", lambda *a, **k: rows):
        ranking = pcap_parser.rank_hosts("dummy.pcap")
    assert ranking[0]["ip"] == "73.124.22.98"
    assert ranking[0]["ranking_scope"].startswith("semua host")
    assert not any(h["is_private"] for h in ranking)


def test_protocol_probe_skips_inapplicable_modules():
    """
    Probe protokol mencegah belasan pass tshark yang pasti nihil. `None` berarti
    probe tidak dijalankan -- jangan melewatkan modul apa pun karena ragu.
    """
    from backend.services.pcap_parser import has_protocol
    web_only = {"frame": 88862, "eth": 88862, "ip": 88862, "tcp": 88740, "http": 83418}
    assert has_protocol(web_only, "http")
    assert not has_protocol(web_only, "kerberos")
    assert not has_protocol(web_only, "tls", "ssl")
    assert has_protocol(None, "kerberos"), "tanpa probe, jangan lewati apa pun"


def test_nbns_wildcard_is_not_a_hostname():
    assert _clean_hostname("*<00>") == ""
    assert _clean_hostname("*") == ""
    assert _clean_hostname("SERVER<20> (Server service)") == "SERVER"


def test_master_timeline_mixes_sources_without_crashing():
    """Tiap sumber evidence memakai format waktu berbeda -- ini yang dulu TypeError."""
    timeline = cross_evidence_correlator.build_master_timeline(
        ("pcap", [{"timestamp": 1700000000.5, "description": "a"}]),
        ("disk_image", [{"timestamp": 1600000000, "description": "b"}]),
        ("metadata", [{"timestamp": "2026:01:31 10:00:00", "description": "c"}]),
        ("unknown", [{"timestamp": None, "description": "d"}]),
    )
    assert [e["description"] for e in timeline] == ["b", "a", "c", "d"]
    assert timeline[0]["evidence_source"] == "disk_image"


def test_hash_match_across_sources():
    sha = "a" * 64
    result = cross_evidence_correlator.correlate_hashes(
        {"evidence_source": "pcap",
         "carved_files": [{"exact_hashes": {"sha256": sha}, "filename": "x.exe"}]},
        {"evidence_source": "disk",
         "analyzed_files": [{"exact_hashes": {"sha256": sha}, "filename": "y.exe"}]})
    assert len(result) == 1 and result[0]["confidence"] == "HIGH"


# ---------- Disk image (parser bodyfile TSK) ----------

def _parse_bodyfile(lines: str) -> list[dict]:
    """Jalankan parser disk_image_analyzer terhadap output fls yang sudah diketahui."""
    from unittest.mock import patch
    from backend.services import disk_image_analyzer as d
    with patch.object(d, "available", lambda: True), \
         patch.object(d, "run", lambda *a, **k: lines), \
         patch.object(d.tools, "resolve", lambda name: name):
        return d.list_files_recursive("dummy.dd")


BODYFILE = (
    "0|/NOTES.TXT|3|r/rrwxrwxrwx|0|0|31|1735660800|1735790880|0|1735704000\n"
    "0|/_ECRET.TXT (deleted)|4|r/rrwxrwxrwx|0|0|58|1735660801|1735790881|0|1735704001\n"
    "0|/$MBR|327027|v/v---------|0|0|512|0|0|0|0\n"
    "0|/$OrphanFiles|327030|V/V---------|0|0|0|0|0|0|0\n"
)


def test_bodyfile_has_eleven_fields_not_twelve():
    """
    Bug yang diperbaiki: format bodyfile TSK punya TEPAT 11 field
    (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime).
    Menuntut 12 field membuat SETIAP baris dilewati -- modul mengembalikan
    daftar kosong tanpa error, seolah image-nya memang tidak berisi apa-apa.
    """
    files = _parse_bodyfile(BODYFILE)
    assert len(files) == 2, f"harusnya 2 berkas nyata, dapat {len(files)}"


def test_bodyfile_time_indices_not_shifted():
    """Indeks waktu ikut geser satu kalau format dikira 12 field."""
    notes = _parse_bodyfile(BODYFILE)[0]
    assert notes["file_path"] == "/NOTES.TXT"
    assert notes["size_bytes"] == 31
    assert notes["atime"] == 1735660800
    assert notes["mtime"] == 1735790880
    assert notes["ctime"] is None        # nilai 0 = tidak diset
    assert notes["crtime"] == 1735704000


def test_deleted_flag_and_virtual_entries():
    files = _parse_bodyfile(BODYFILE)
    deleted = [f for f in files if f["is_deleted"]]
    assert len(deleted) == 1 and deleted[0]["file_path"] == "/_ECRET.TXT"
    # $MBR (v/v) dan $OrphanFiles (V/V huruf BESAR) sama-sama entry virtual TSK.
    # Filter case-sensitive melewatkan yang huruf besar.
    assert not any("$" in f["file_path"] for f in files)


def test_mac_timeline_emits_one_event_per_timestamp():
    """
    Satu berkas punya sampai 4 stempel waktu yang bisa berjauhan. Menggabungkan
    jadi satu baris menyembunyikan justru yang dicari: apa yang terjadi pada
    rentang waktu tertentu.
    """
    from unittest.mock import patch
    from backend.services import disk_image_analyzer as d
    # Parsing dilakukan DULU, di luar patch. Kalau lambda-nya memanggil
    # _parse_bodyfile (yang sendiri mem-patch list_files_recursive), hasilnya
    # rekursi tak berujung.
    parsed = _parse_bodyfile(BODYFILE)
    with patch.object(d, "list_files_recursive", lambda *a, **k: parsed):
        timeline = d.build_mac_timeline("dummy.dd")
    assert len(timeline) == 6          # 2 berkas x 3 stempel non-nol
    assert [e["timestamp"] for e in timeline] == sorted(e["timestamp"] for e in timeline)
    assert {e["action"] for e in timeline} == {"Accessed", "Modified", "Created"}


# ---------- Inventaris host & layanan terekspos ----------

def test_oui_identifies_virtual_machines():
    """
    Pertanyaan 'apakah mesin ini virtual?' mengubah kesimpulan yang boleh
    ditulis: 'penyerang menembus perimeter organisasi' jadi klaim salah kalau
    ternyata dua VM di host yang sama.
    """
    from backend.services.host_inventory import lookup_oui
    vbox = lookup_oui("08:00:27:26:b6:da")
    assert vbox["is_virtual"] and "VirtualBox" in vbox["vendor"]
    assert lookup_oui("00:15:5d:01:02:03")["is_virtual"]      # Hyper-V
    assert lookup_oui("00:50:56:aa:bb:cc")["is_virtual"]      # VMware
    unknown = lookup_oui("d4:3d:7e:11:22:33")
    assert not unknown["is_virtual"] and unknown["vendor"] is None
    assert "IEEE" in unknown["note"]   # arahkan ke lookup manual, jangan diam


def test_locally_administered_mac_detected():
    """Bit U/L menandakan MAC di-set manual atau diacak -- bisa privasi, bisa penyamaran."""
    from backend.services.host_inventory import lookup_oui
    assert lookup_oui("02:42:ac:11:00:02")["locally_administered"]   # bit ke-2 menyala
    assert not lookup_oui("08:00:27:26:b6:da")["locally_administered"]


def test_exposed_services_only_counts_inbound():
    from backend.services.protocol_anomaly import map_exposed_services
    sessions = [
        {"direction": "inbound", "dst_port": 445, "dst_ip": "10.0.2.4",
         "has_payload": False, "time_utc": "t", "timestamp": 1},
        {"direction": "inbound", "dst_port": 80, "dst_ip": "10.0.2.4",
         "has_payload": True, "time_utc": "t", "timestamp": 2},
        {"direction": "outbound", "dst_port": 443, "dst_ip": "8.8.8.8",
         "has_payload": False, "time_utc": "t", "timestamp": 3},
    ]
    services = map_exposed_services(sessions, "10.0.2.15")
    ports = {s["port"] for s in services}
    assert ports == {445, 80}, "port tujuan koneksi KELUAR bukan layanan yang diekspos"
    assert next(s for s in services if s["port"] == 445)["service"] == "SMB"


def test_port_scan_reports_widest_window():
    """
    Regresi: berhenti di window pertama yang memenuhi ambang membuat scan 1002
    port dilaporkan sebagai 8 port -- dan justru angka itu yang ditanyakan.
    """
    from backend.services.protocol_anomaly import detect_port_scan
    sessions = [{"direction": "inbound", "dst_port": p, "dst_ip": "10.0.2.4",
                 "has_payload": False, "timestamp": 1000 + p * 0.05,
                 "time_utc": "2024-09-10 05:44:28 UTC"} for p in range(1, 61)]
    hits = detect_port_scan(sessions, "10.0.2.15")
    assert len(hits) == 1
    assert hits[0]["port_count"] == 60, f"harus window terluas, dapat {hits[0]['port_count']}"
    assert hits[0]["source_ip"] == "10.0.2.4"


def test_repeated_ports_are_not_a_scan():
    """Klien sungguhan menyambung ulang ke port yang sama; scanner tidak."""
    from backend.services.protocol_anomaly import detect_port_scan
    sessions = [{"direction": "inbound", "dst_port": 80 + (i % 3), "dst_ip": "10.0.2.4",
                 "has_payload": True, "timestamp": 1000 + i,
                 "time_utc": "t"} for i in range(60)]
    assert detect_port_scan(sessions, "10.0.2.15") == []


# ---------- SMB & sidik jari perkakas ----------

def test_header_lines_stripped_of_literal_crlf():
    r"""
    `-T fields` meng-escape CRLF jadi TEKS literal '\r\n', bukan karakter
    kontrol. Membiarkannya membuat tiap baris header di laporan berakhiran
    sampah yang terlihat seperti kesalahan penyalinan.
    """
    from backend.services.http_analyzer import _split_headers
    raw = r"Host: 10.0.2.15\r\n|Connection: Keep-Alive\r\n|Accept: */*\r\n"
    assert _split_headers(raw) == ["Host: 10.0.2.15", "Connection: Keep-Alive",
                                   "Accept: */*"]
    assert _split_headers("") == []
    assert _split_headers(r"\r\n") == []


def test_header_separator_is_not_comma():
    """
    Koma lazim muncul DI DALAM nilai header (Accept, Cache-Control), jadi
    memakainya sebagai pemisah akan memotong satu header jadi beberapa baris.
    """
    from backend.services.http_analyzer import HEADER_SEPARATOR, _split_headers
    assert HEADER_SEPARATOR != ","
    raw = r"Accept: text/html,application/xhtml+xml\r\n|Host: x\r\n"
    assert _split_headers(raw) == ["Accept: text/html,application/xhtml+xml", "Host: x"]


def test_body_clipped_with_marker():
    """Body megabyte membengkakkan hasil tanpa menambah nilai analisis."""
    from backend.services.http_analyzer import MAX_BODY_CHARS, _clip
    assert _clip("x" * 100) == "x" * 100
    clipped = _clip("y" * (MAX_BODY_CHARS + 500))
    assert len(clipped) == MAX_BODY_CHARS + 1 and clipped.endswith("…")


def test_session_summary_includes_response_code():
    """Daftar request tanpa response tidak menjawab: apakah permintaan berhasil?"""
    from backend.services.http_analyzer import summarize
    items = [{"request": {"method": "GET", "uri": "/robots.txt", "host": "10.0.2.15"},
              "response": {"status_code": 404}},
             {"request": {"method": "POST", "uri": "/upload", "host": "10.0.2.15"},
              "response": None}]
    text = summarize(items)
    assert "GET 10.0.2.15/robots.txt -> 404" in text
    assert "-> (tanpa response)" in text


def test_smb_unc_backslashes_unescaped():
    r"""
    tshark menggandakan backslash pada field UNC: nilai mentah
    `\\\\10.0.2.15\\IPC$` sebenarnya berarti `\\10.0.2.15\IPC$`. Menyalinnya apa
    adanya ke laporan menghasilkan path yang tidak bisa dipakai siapa pun.
    """
    from backend.services.smb_analyzer import _unescape
    assert _unescape(r"\\\\10.0.2.15\\IPC$") == r"\\10.0.2.15\IPC$"
    assert _unescape(r"\\\\SERVER\\Documents") == r"\\SERVER\Documents"


def test_web_executable_extensions_flagged():
    """Berkas yang bisa dieksekusi web server, ditaruh lewat SMB = jalur RCE."""
    from backend.services.smb_analyzer import WEB_EXECUTABLE
    for name in ("shell.aspx", "cmd.asp", "backdoor.php", "x.jsp", "run.exe"):
        assert name.endswith(WEB_EXECUTABLE), name
    for name in ("information.txt", "web.config", "report.pdf", "logo.png"):
        assert not name.endswith(WEB_EXECUTABLE), f"{name} bukan executable web"


def test_admin_shares_distinguished():
    """IPC$ diakses itu wajar; share biasa adalah tempat berkas bisa ditaruh."""
    from backend.services.smb_analyzer import ADMIN_SHARES
    assert "ipc$" in ADMIN_SHARES and "c$" in ADMIN_SHARES
    assert "documents" not in ADMIN_SHARES and "wwwroot" not in ADMIN_SHARES


def test_user_agent_identifies_attack_tools():
    from backend.services.tool_fingerprint import classify
    nmap = classify("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/)")
    assert nmap["tool"] == "Nmap" and nmap["is_attack_tool"]
    assert classify("sqlmap/1.8#stable")["tool"] == "sqlmap"
    assert classify("Nikto/2.5.0")["tool"] == "Nikto"
    # Komponen Windows bukan alat serangan -- jangan dilaporkan sebagai penyerang.
    windows = classify("Microsoft-CryptoAPI/10.0")
    assert not windows["is_attack_tool"]
    browser = classify("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0")
    assert browser["tool"] is None and not browser["is_attack_tool"]


# ---------- Identifikasi packer ----------

def test_upx_identified_by_section_names():
    """
    'entropy tinggi' hanya bilang datanya terkompresi, bukan PACKER APA.
    Nama packer menentukan cara membongkarnya.
    """
    from backend.services.binary_analyzer import identify_packer
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "packed.exe"
        path.write_bytes(b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100)
        result = identify_packer(path, ["UPX0", "UPX1", ".rsrc"])
    assert result["packer"] == "UPX"
    assert result["confidence"] == "HIGH" and result["marker_found"]
    assert "upx -d" in result["hint"]


def test_unknown_packer_says_so_instead_of_guessing():
    from backend.services.binary_analyzer import identify_packer
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "normal.exe"
        path.write_bytes(b"MZ" + b"\x00" * 200)
        result = identify_packer(path, [".text", ".data", ".rsrc"])
    assert result["packer"] is None and result["confidence"] == "LOW"
    assert "packer khusus" in result["hint"]   # arahkan, jangan diam


def test_pcap_extensions_recognised_everywhere():
    """
    Daftar ekstensi yang disalin-salin adalah cara paling gampang membuat
    '.pcapng' dikenali di satu jalur tapi tidak di jalur lain. Sebelumnya
    `analyze_file capture.pcapng` memindai steganografi pada tangkapan
    lalu lintas, bukan menganalisis lalu lintasnya.
    """
    from backend import config
    for name in ("capture.pcapng", "CAPTURE.PCAPNG", "a.pcap", "b.cap",
                 "c.pcapng.gz", "/mnt/c/data/evidence.pcapng"):
        assert config.is_pcap(name), name
    for name in ("gambar.jpg", "dump.mem", "disk.dd", "app.apk", "pcapng.txt"):
        assert not config.is_pcap(name), name


# ---------- Pembongkaran ----------

def test_domain_filter_rejects_code_identifiers():
    """
    Tanpa daftar TLD, strings dari binary menghasilkan 'domain' seperti
    'autoit.error' dan 'function.hcan' -- potongan pesan error dan nama fungsi.
    Melaporkannya sebagai IOC membuat seluruh daftar tidak bisa dipercaya.
    """
    from backend.services.binary_analyzer import _plausible_domain
    for junk in ("autoit.error", "function.hcan", "statement.orecursion",
                 "declared.xarray", "msvcrt.dll", "config.json", "item.count"):
        assert not _plausible_domain(junk), f"{junk} bukan domain"
    for real in ("evil-c2.com", "cdn.example.org", "panel.duckdns.org",
                 "taibeinan.cc", "filemegahab4.sbs"):
        assert _plausible_domain(real), f"{real} domain sungguhan"


def test_runtime_identified_from_strings():
    """'Dropper AutoIt' dan 'RAT .NET' adalah dua dunia berbeda saat atribusi."""
    from backend.services.binary_analyzer import identify_runtime
    assert identify_runtime(["blah", "AU3!EA06", "x"])["runtime"] == "AutoIt"
    assert identify_runtime(["mscoree.dll"])["runtime"] == ".NET"
    assert identify_runtime(["PyInstaller", "_MEIPASS"])["runtime"] == "PyInstaller"
    assert identify_runtime(["hello world"])["runtime"] is None


def test_zip_slip_entries_rejected():
    """
    Nama entry berasal dari pembuat arsip: '../../evil' menulis DI LUAR
    direktori tujuan. Harus ditolak sebelum apa pun menyentuh disk.
    """
    import zipfile
    from backend.services.unpacker import unpack_zip
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "evil.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("aman.txt", "isi biasa")
            z.writestr("../../keluar.txt", "mencoba lolos")
        out = Path(tmp) / "hasil"
        result = unpack_zip(archive, out)
        assert result["success"]
        assert any("zip slip" in r["reason"] for r in result["rejected"])
        assert not (Path(tmp).parent / "keluar.txt").exists()
        assert any("aman.txt" in f for f in result["files"])


def test_zip_bomb_ratio_rejected():
    """Arsip kecil yang mengembang ekstrem: satu berkas bukti tidak boleh memenuhi disk."""
    import zipfile
    from backend.services.unpacker import unpack_zip
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "bomb.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("bom.bin", "0" * 5_000_000)   # rasio kompresi sangat tinggi
            z.writestr("kecil.txt", "isi biasa yang tidak terlalu terkompresi")
        result = unpack_zip(archive, Path(tmp) / "hasil")
        assert any("zip bomb" in r["reason"] for r in result["rejected"])


def test_upx_unpack_never_touches_original():
    """
    Bukti tidak boleh diubah. upx membongkar di tempat secara bawaan, jadi
    berkasnya WAJIB disalin dulu -- kalau tidak, hash evidence berubah.
    """
    import inspect
    from backend.services import unpacker
    source = inspect.getsource(unpacker.unpack_upx)
    assert "copy.write_bytes" in source, "harus menyalin sebelum membongkar"
    assert "-d" in source


# ---------- Memory (parser command line Volatility) ----------

STARTUP_PATH = (r'"C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu'
                r'\Programs\Startup\update.exe" ')


def test_executable_from_cmdline_handles_spaces_in_path():
    """
    Bug yang diperbaiki: memotong command line di spasi pertama.
    Path Windows penuh spasi, dan lokasi yang paling sering dipakai malware
    ('...\\Start Menu\\Programs\\Startup\\') termasuk di dalamnya -- hasilnya
    terpotong jadi '...\\Start', bukan .exe, dan baris itu dilewati diam-diam.
    """
    from backend.services.memory_analyzer import _executable_from_cmdline as parse
    assert parse(STARTUP_PATH) == "update.exe"
    assert parse(r'C:\Windows\System32\svchost.exe -k netsvcs') == "svchost.exe"
    assert parse(r'"C:\Program Files (x86)\App\run.exe" /c') == "run.exe"
    assert parse("bukan sebuah path") is None


def test_process_hollowing_detected():
    """RegSvcs.exe menjalankan update.exe = masquerading, dari dump uji sungguhan."""
    from backend.services.memory_analyzer import find_name_path_mismatch
    findings = find_name_path_mismatch([
        {"PID": 4200, "Process": "RegSvcs.exe", "Args": STARTUP_PATH},
        {"PID": 900, "Process": "updatenow.exe",
         "Args": r'"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"'},
        {"PID": 4, "Process": "System", "Args": ""},
    ])
    assert len(findings) == 1, f"harusnya cuma RegSvcs yang kena: {findings}"
    assert findings[0]["process_name"] == "RegSvcs.exe"
    assert findings[0]["commandline_binary"] == "update.exe"
    assert findings[0]["confidence"] == "HIGH"


def test_startup_folder_is_flagged_not_only_temp():
    """
    Memeriksa '\\temp\\' saja MELEWATKAN persistence folder Startup -- terbukti
    pada dump uji, di mana satu-satunya proses berbahaya berjalan dari sana.
    """
    from backend.services.memory_analyzer import flag_suspicious_cmdlines
    flagged = flag_suspicious_cmdlines(
        [{"PID": 4200, "Process": "RegSvcs.exe", "Args": STARTUP_PATH}])
    assert flagged and any("Startup" in r for r in flagged[0]["reasons"])
    assert flagged[0]["confidence"] == "MEDIUM"


def test_reverse_shell_to_private_ip_not_filtered_out():
    """
    Regresi: menyaring koneksi hanya ke "IP eksternal" menyembunyikan temuan
    terpenting. Pada lab dan serangan lateral, penyerang berada di alamat
    PRIVAT -- reverse shell w3wp.exe -> 10.0.2.4:4443 tersaring keluar justru
    karena ia tetangga sesubnet.
    """
    from backend.services.memory_analyzer import notable_connections
    conns = [
        {"Owner": "w3wp.exe", "PID": 4332, "LocalAddr": "10.0.2.15", "LocalPort": 49688,
         "ForeignAddr": "10.0.2.4", "ForeignPort": 4443, "State": "CLOSED"},
        {"Owner": "System", "PID": 4, "LocalAddr": "0.0.0.0", "LocalPort": 445,
         "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING"},
        {"Owner": "chrome.exe", "PID": 900, "LocalAddr": "10.0.2.15", "LocalPort": 50001,
         "ForeignAddr": "10.0.2.9", "ForeignPort": 443, "State": "ESTABLISHED"},
    ]
    result = notable_connections(conns)
    processes = [c["process"] for c in result]
    assert "w3wp.exe" in processes, "reverse shell ke IP privat WAJIB muncul"
    assert result[0]["confidence"] == "HIGH"
    assert any("pembalikan peran" in r for r in result[0]["reasons"])
    assert "System" not in processes, "socket LISTENING bukan koneksi keluar"
    assert "chrome.exe" not in processes, "browser ke port 443 lokal itu wajar"


def test_suspicious_port_flagged_even_for_ordinary_process():
    from backend.services.memory_analyzer import notable_connections
    result = notable_connections([
        {"Owner": "notepad.exe", "PID": 123, "LocalAddr": "10.0.0.5", "LocalPort": 5000,
         "ForeignAddr": "10.0.0.9", "ForeignPort": 4444, "State": "ESTABLISHED"}])
    assert len(result) == 1 and result[0]["confidence"] == "HIGH"
    assert any("4444" in r for r in result[0]["reasons"])


def test_defender_in_programdata_downgraded_not_hidden():
    """Windows Defender memang tinggal di ProgramData -- ditandai LOW, tetap dilaporkan."""
    from backend.services.memory_analyzer import flag_suspicious_cmdlines
    flagged = flag_suspicious_cmdlines([{
        "PID": 2632, "Process": "MsMpEng.exe",
        "Args": r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"'}])
    assert len(flagged) == 1, "tidak boleh disembunyikan dari hasil"
    assert flagged[0]["confidence"] == "LOW"
    assert flagged[0]["known_legitimate"]


def test_windows_reserved_names_recognised():
    """
    Nama objek HTTP diambil dari URL, jadi DIKENDALIKAN PENYERANG. Satu request
    ke '/nul' membuat tshark menulis berkas bernama device Windows, yang tidak
    bisa dihapus lewat API biasa dan menetap selamanya di direktori carving.
    Terjadi sungguhan saat menganalisis WebInvestigation.pcap.
    """
    from backend.services.file_carver import WINDOWS_RESERVED
    for name in ("nul", "con", "aux", "com1", "lpt9", "prn"):
        assert name in WINDOWS_RESERVED
    for name in ("index", "logo", "search", "nulla", "console"):
        assert name not in WINDOWS_RESERVED, f"{name} berkas biasa, jangan dibuang"


def test_force_unlink_survives_missing_and_odd_names():
    import os
    from backend.services.file_carver import _force_unlink, extended_path
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "biasa.bin"
        path.write_bytes(b"x" * 10)
        _force_unlink(path)
        assert not path.exists()
        _force_unlink(Path(tmp) / "tidak-ada.bin")   # tidak boleh melempar

        if os.name != "nt":
            return
        # Berkas bernama device hanya bisa DIBUAT lewat path extended juga.
        reserved = Path(tmp) / "nul"
        with open(extended_path(reserved), "wb") as f:
            f.write(b"objek HTTP dari URL /nul")
        assert os.path.exists(extended_path(reserved))
        _force_unlink(reserved)
        assert not os.path.exists(extended_path(reserved)), \
            "berkas bernama device harus terhapus, bukan menetap selamanya"


def test_abspath_collapses_reserved_names():
    """
    Akar penyebabnya, dikunci sebagai test: os.path.abspath('dir/nul') sendiri
    yang meruntuhkan path jadi perangkat. Membangun path extended darinya
    menghasilkan string rusak dan penghapusan gagal.
    """
    import os
    if os.name != "nt":
        return
    assert os.path.abspath("dir/nul") == "\\\\.\\nul"
    from backend.services.file_carver import extended_path
    built = extended_path(Path("dir") / "nul")
    assert built.endswith("\\dir\\nul") and built.startswith("\\\\?\\")


def test_delete_removes_upload_not_just_record():
    """
    Menghapus record saja meninggalkan pcap ratusan MB di storage/uploads tanpa
    apa pun yang menunjuk ke sana -- riwayat tampak bersih, disk tidak.
    """
    import json
    from unittest.mock import patch
    from backend import config as settings
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # 'carved' wajib bernama persis: _delete_one mencarinya di STORAGE/carved.
        analyses, uploads, carved = root / "analyses", root / "uploads", root / "carved"
        for d in (analyses, uploads, carved):
            d.mkdir()
        (analyses / "abc123.json").write_text(json.dumps({"analysis_id": "abc123"}))
        (uploads / "abc123_capture.pcap").write_bytes(b"x" * 100)
        (carved / "abc123_capture" / "http").mkdir(parents=True)
        (carved / "abc123_capture" / "http" / "payload.exe").write_bytes(b"MZ")

        with patch.object(settings, "ANALYSIS_DIR", analyses), \
             patch.object(settings, "UPLOAD_DIR", uploads), \
             patch.object(settings, "STORAGE", root):
            from backend import main
            removed = main._delete_one("abc123")

        # Diperiksa DI DALAM blok: begitu TemporaryDirectory keluar, seluruh
        # direktorinya lenyap dan iterdir() gagal dengan FileNotFoundError --
        # bukan karena kodenya salah, tapi karena testnya memeriksa terlalu telat.
        assert removed == {"record": 1, "uploads": 1, "carved": 1}
        assert not list(analyses.glob("*.json"))
        assert not list(uploads.iterdir())
        assert not list(carved.iterdir())


def test_stage_parsing_for_progress_bar():
    """
    Pesan progress pipeline ('[3/9] ...') diurai jadi angka tahap supaya GUI
    bisa menampilkan kemajuan NYATA, bukan animasi yang cuma berputar.
    """
    from backend.main import _STAGE
    match = _STAGE.match("[3/9] Ekstraksi identitas 10.1.21.58...")
    assert match and match.group(1) == "3" and match.group(2) == "9"
    assert match.group(3) == "Ekstraksi identitas 10.1.21.58..."
    assert _STAGE.match("[1/3] Hash + deteksi tipe berkas...").group(2) == "3"
    assert _STAGE.match("menyiapkan") is None   # pesan tanpa nomor tetap aman


def test_all_pipeline_stages_numbered_consistently():
    """Penomoran tahap yang tidak konsisten membuat bar melompat mundur."""
    import re
    from pathlib import Path
    source = (Path(__file__).resolve().parent.parent / "backend" / "analyze.py").read_text(
        encoding="utf-8")
    totals = set(re.findall(r'progress\("\[\d+/(\d+)\]', source))
    assert len(totals) == 1, f"total tahap tidak seragam: {totals}"


# ---------- Parsing output tool ----------

def test_capinfos_float_survives_comma_decimal_locale():
    """
    capinfos memformat desimal mengikuti LOCALE sistem. Di mesin Indonesia/Jerman
    nilainya '623,925423' -- float() gagal dan seluruh info waktu capture diam-diam
    jadi None, termasuk di narasi laporan.
    """
    from backend.services.pcap_parser import _float, _int
    assert _float("623,925423 seconds") == 623.925423     # locale koma
    assert _float("623.925423 seconds") == 623.925423     # locale titik
    assert _float("1769576643,908927") == 1769576643.908927
    assert _float("1,234.56") == 1234.56                  # koma = pemisah ribuan
    assert _float(None) is None and _float("n/a") is None
    assert _int("51181") == 51181 and _int("51,181") == 51181


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
