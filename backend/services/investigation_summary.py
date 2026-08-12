"""
Ringkasan investigasi: pertanyaan baku yang selalu ditanyakan, dijawab langsung
dari hasil analisis.

Modul lain menghasilkan DATA. Modul ini menyusunnya jadi JAWABAN atas pertanyaan
yang sebenarnya diajukan orang saat membuka sebuah kasus: siapa korbannya, siapa
penyerangnya, lewat mana masuknya, apa yang ditinggalkan.

Aturan yang dipegang: kalau evidence tidak memuat jawabannya, katakan begitu.
Jawaban yang dikarang lebih berbahaya daripada kolom kosong -- pembaca laporan
tidak punya cara membedakan keduanya.
"""

UNANSWERED = "Tidak terjawab dari evidence ini"


def _q(question, answer, confidence="MEDIUM", query=None, caveat=None, detail=None):
    return {"question": question, "answer": answer, "confidence": confidence,
            "evidence_query": query, "caveat": caveat, "detail": detail or []}


def summarize(result: dict, memory: dict | None = None,
              correlations: list[dict] | None = None) -> list[dict]:
    memory = memory or {}
    correlations = correlations or []
    answers = [
        _who_is_who(result),
        _physical_or_virtual(result),
        _reconnaissance(result),
        _exposed(result),
        _entry_point(result, memory, correlations),
        _outbound(result, memory),
        _persistence(memory),
        _files(result),
        _what_is_not_answerable(result, memory),
    ]
    return [a for a in answers if a]


def _who_is_who(result: dict) -> dict:
    inv = result.get("inventory") or {}
    ranking = result.get("host_ranking") or []
    identity = result.get("identity") or {}
    scans = result.get("port_scans") or []
    attackers = sorted({s["source_ip"] for s in scans})
    if not attackers:
        attackers = sorted({f["src_ip"] for f in result.get("owasp_findings", [])
                            if "Injection" in f["owasp_category"]
                            or "Traversal" in f["owasp_category"]})

    detail = [f"{h['ip']}: {h['packets_total']} paket "
              f"({h['packets_sent']} kirim / {h['packets_received']} terima)"
              for h in ranking[:4]]
    answer = f"Host yang dianalisis: {identity.get('ip')}"
    if attackers:
        answer += f". Sumber serangan: {', '.join(attackers)}"
    return _q(
        "Siapa korban dan siapa penyerangnya?", answer,
        confidence="HIGH" if attackers else "MEDIUM",
        query=f"ip.addr=={identity.get('ip')}",
        detail=detail + [
            f"{inv.get('layer2_device_count', 0)} perangkat di layer 2 "
            f"({inv.get('host_count', 0)} host + {inv.get('gateway_count', 0)} gateway) "
            f"dari {inv.get('ip_count_total', 0)} IP unik"],
        caveat="Target dipilih dari total paket dua arah. Host yang paling banyak "
               "MENGIRIM biasanya penyerang, bukan korban -- periksa peringkat di atas "
               "sebelum menerima tebakan ini." if not attackers else None)


def _physical_or_virtual(result: dict) -> dict | None:
    inv = result.get("inventory") or {}
    devices = inv.get("devices") or []
    if not devices:
        return None
    virtual = [d for d in devices if d["is_virtual"] and d["role"] == "host"]
    hosts = [d for d in devices if d["role"] == "host"]
    if not virtual:
        return _q("Mesin fisik atau virtual?",
                  "Tidak ada OUI virtualisasi yang dikenali", confidence="LOW",
                  caveat="Tabel OUI di sini hanya memuat vendor yang penting secara "
                         "forensik. Vendor tak dikenal perlu dicek manual di basis data IEEE.")
    vendors = sorted({d["vendor"] for d in virtual})
    return _q(
        "Mesin fisik atau virtual?",
        f"Virtual — {len(virtual)} dari {len(hosts)} host memakai OUI {', '.join(vendors)}",
        confidence="HIGH", query="eth.src",
        detail=[f"{d['mac']} = {', '.join(d['ip_addresses'][:2])} ({d['vendor']})"
                for d in virtual] +
               [f"Penguat: {ip} = {hint}"
                for ip, hint in (inv.get("virtualbox_nat_indicators") or {}).items()],
        caveat="Bukti berasal dari lab/sandbox, bukan jaringan produksi. Hindari "
               "kesimpulan tentang 'perimeter organisasi' di laporan.")


def _reconnaissance(result: dict) -> dict:
    scans = result.get("port_scans") or []
    if not scans:
        return _q("Apakah ada aktivitas pemindaian?",
                  "Tidak terdeteksi pola pemindaian port", confidence="MEDIUM",
                  caveat="Pemindaian lambat (satu port per beberapa menit) tidak akan "
                         "tertangkap oleh jendela deteksi 120 detik.")
    top = max(scans, key=lambda s: s["port_count"])
    return _q(
        "Apakah ada aktivitas pemindaian?",
        f"Ya — {top['source_ip']} memindai {top['port_count']} port dalam "
        f"{top['duration_sec']} detik",
        confidence="HIGH", query=top["evidence_query"],
        detail=[f"Mulai {top['window_start_utc']}",
                f"{top['single_touch_ports']} port hanya disentuh sekali",
                f"Port awal: {', '.join(str(p) for p in top['ports_scanned'][:15])}…"],
        caveat="Jumlah port mendekati 1000 dengan satu sentuhan per port adalah "
               "perilaku khas pemindai otomatis dengan setelan bawaan."
               if top["port_count"] > 900 else None)


def _exposed(result: dict) -> dict | None:
    services = result.get("exposed_services") or []
    if not services:
        return None
    # Layanan yang benar-benar dipakai punya PAYLOAD. Sisanya hanya sisa pemindaian
    # -- membedakan keduanya mencegah laporan mendaftar 40 'layanan' yang tidak ada.
    real = [s for s in services if s["sessions_with_payload"] or s["connection_count"] > 2]
    scanned_only = len(services) - len(real)
    return _q(
        "Layanan apa yang terekspos di host ini?",
        ", ".join(f"{s['port']}/tcp ({s['service']})" for s in real) or "tidak ada",
        confidence="HIGH", query=real[0]["evidence_query"] if real else None,
        detail=[f"{s['port']}/tcp {s['service']}: {s['connection_count']} koneksi, "
                f"{s['sessions_with_payload']} berpayload" for s in real],
        caveat=f"{scanned_only} port lain hanya muncul sekali sebagai bagian dari "
               "pemindaian — itu bukan layanan yang berjalan." if scanned_only else None)


def _entry_point(result: dict, memory: dict, correlations: list) -> dict:
    services = result.get("exposed_services") or []
    with_payload = [s for s in services if s["sessions_with_payload"]]
    if not with_payload:
        return _q("Bagaimana penyerang masuk?", UNANSWERED, confidence="LOW",
                  caveat="Tidak ada sesi masuk yang berisi payload terbaca. Kalau "
                         "layanannya terenkripsi (HTTPS/SMB3), isi serangannya memang "
                         "tidak bisa dilihat tanpa kunci dekripsi.")
    main = max(with_payload, key=lambda s: s["sessions_with_payload"])
    match = next((c for c in correlations
                  if c.get("type") == "service_process_match" and c.get("port") == main["port"]), None)
    process = match["process_name"] if match else None

    detail = [f"{main['connection_count']} koneksi masuk ke {main['port']}/tcp, "
              f"{main['sessions_with_payload']} berisi payload",
              f"Sumber: {', '.join(main['distinct_sources'])}",
              f"Pertama kali {main['first_seen_utc']}"]
    caveat = None
    if process in ("System", "svchost.exe"):
        # Di Windows, port 80 dipegang HTTP.sys di kernel, sehingga netscan
        # melaporkannya atas nama 'System'. Menyebut 'System' sebagai layanan yang
        # diserang benar secara teknis tapi tidak menjawab apa pun.
        workers = [p.get("ImageFileName") for p in memory.get("processes", [])
                   if str(p.get("ImageFileName") or "").lower()
                   in ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "inetinfo.exe")]
        if workers:
            process = f"{process} (kernel) — proses pekerja sebenarnya: {', '.join(set(workers))}"
        caveat = ("'System' PID 4 adalah HTTP.sys/SMB di kernel, bukan aplikasinya. "
                  "Cari proses pekerja (mis. w3wp.exe untuk IIS) sebelum menyebut "
                  "layanan apa yang diserang.")

    return _q(
        "Bagaimana penyerang masuk?",
        f"Lewat {main['port']}/tcp ({main['service']})"
        + (f", dilayani {process}" if process else ""),
        confidence="HIGH" if process else "MEDIUM",
        query=main["evidence_query"], detail=detail, caveat=caveat)


def _outbound(result: dict, memory: dict) -> dict | None:
    """
    Koneksi KELUAR dari proses server adalah pembalikan peran yang tidak wajar.

    Server menerima koneksi; ia tidak menghubungi kliennya kembali di port acak.
    Satu baris koneksi keluar dari w3wp.exe lebih berarti daripada ribuan koneksi
    masuk, karena masuk berarti 'dicoba' sedangkan keluar berarti 'berhasil'.
    """
    server_processes = ("w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe",
                        "tomcat.exe", "inetinfo.exe", "java.exe", "php-cgi.exe")
    suspicious = []
    for conn in memory.get("connections", []):
        owner = str(conn.get("Owner") or "").lower()
        foreign, port = conn.get("ForeignAddr"), conn.get("ForeignPort")
        if owner in server_processes and foreign and port not in (0, None):
            suspicious.append(conn)

    c2 = [e for e in result.get("key_events", []) if e.get("category") == "http_candidate_c2"]
    if not suspicious and not c2:
        return None

    detail = [f"{c.get('Owner')} (PID {c.get('PID')}) -> {c.get('ForeignAddr')}:"
              f"{c.get('ForeignPort')} [{c.get('State')}]" for c in suspicious]
    detail += [f"{e['destination']} sejak {e['time_utc']}" for e in c2]
    return _q(
        "Apakah ada koneksi keluar yang tidak wajar?",
        (f"Ya — {suspicious[0].get('Owner')} membuka koneksi KELUAR ke "
         f"{suspicious[0].get('ForeignAddr')}:{suspicious[0].get('ForeignPort')}"
         if suspicious else f"{len(c2)} destinasi HTTP kandidat C2"),
        confidence="HIGH" if suspicious else "MEDIUM",
        query="vol -f <dump> windows.netscan" if suspicious else (c2[0]["evidence_query"] if c2 else None),
        detail=detail,
        caveat="Proses server yang MENGHUBUNGI klien di port tinggi adalah pembalikan "
               "peran: pola khas reverse shell setelah eksploitasi berhasil. Koneksi "
               "masuk berarti 'dicoba', koneksi keluar berarti 'berhasil'."
               if suspicious else None)


def _persistence(memory: dict) -> dict | None:
    items = memory.get("persistence") or []
    hollow = memory.get("process_hollowing") or []
    if not items and not hollow:
        return None
    detail = [f"{i['binary'] or i['process']} (PID {i['pid']}) via {i['mechanism']}"
              for i in items]
    detail += [f"{h['process_name']} (PID {h['pid']}) menjalankan {h['commandline_binary']}"
               for h in hollow]
    answer = ", ".join(sorted({i["binary"] or i["process"] for i in items})) or "—"
    return _q(
        "Apa yang ditinggalkan penyerang di sistem?", answer,
        confidence="HIGH", query="vol -f <dump> windows.cmdline",
        detail=detail,
        caveat="Nama proses tidak selalu jujur: proses yang melaporkan diri sebagai A "
               "tapi menjalankan berkas B adalah masquerading/hollowing."
               if hollow else None)


def _files(result: dict) -> dict | None:
    carved = [f for f in (result.get("carved_files") or []) if f.get("confidence") != "LOW"]
    if not carved:
        return None
    return _q(
        "Berkas apa yang berpindah lewat jaringan?",
        f"{len(carved)} berkas menarik berhasil diekstrak",
        confidence="HIGH",
        detail=[f"{f['filename']} ({f['protocol']}, {f['file_size']} B) "
                f"sha256 {f['exact_hashes']['sha256'][:24]}…" for f in carved[:8]],
        caveat="Cocokkan hash-nya dengan berkas lain di evidence pack — hash identik "
               "membuktikan berkasnya sama, nama yang sama tidak membuktikan apa pun.")


def _what_is_not_answerable(result: dict, memory: dict) -> dict:
    """
    Kolom yang paling sering hilang dari laporan pemula, dan paling sering
    ditanyakan penilai: apa yang TIDAK bisa disimpulkan dari bukti ini.
    """
    gaps = []
    if not memory:
        gaps.append("Tanpa RAM dump, lalu lintas tidak bisa dihubungkan ke proses "
                    "yang menghasilkannya")
    if not (result.get("disk") or {}).get("available"):
        gaps.append("Tanpa disk image, waktu berkas malware pertama kali sampai di "
                    "sistem tidak bisa dipastikan")
    skipped = result.get("skipped_modules") or []
    gaps += [f"Dilewati: {s}" for s in skipped]
    encrypted = [s for s in (result.get("exposed_services") or [])
                 if s["port"] in (443, 8443, 993, 995) and not s["sessions_with_payload"]]
    if encrypted:
        gaps.append(f"{len(encrypted)} layanan terenkripsi — isi lalu lintasnya tidak "
                    "terbaca tanpa kunci dekripsi")
    threat = result.get("threat_feed_stats") or {}
    if threat.get("loaded"):
        gaps.append("Tidak cocok dengan threat feed BUKAN berarti aman — feed publik "
                    "hanya memuat yang sudah pernah dilaporkan")
    return _q("Apa yang TIDAK bisa dijawab dari evidence ini?",
              f"{len(gaps)} keterbatasan tercatat", confidence="HIGH", detail=gaps)
