"""
Rekonstruksi kronologi serangan: siapa memulai, kapan, dan data apa yang berpindah.

Berbeda dari `timeline_builder` yang mengurutkan temuan menurut waktu, modul ini
menyusunnya jadi FASE dan menyebut PELAKU tiap langkah. Daftar event tanpa
pelaku membuat pembaca laporan harus menebak sendiri arah serangannya -- dan
tebakan itulah yang paling sering salah.

Tiap event menjawab tiga hal: kapan, siapa yang memulai, dan apa yang berpindah.
"""
from datetime import datetime, timezone

from .timeline_builder import sort_key, to_utc


def _epoch(value) -> float | None:
    """Terima epoch, datetime, atau string UTC dari modul mana pun."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(text[:25], fmt)
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()
        except ValueError:
            continue
    return None

# Fase disusun menurut urutan yang lazim, bukan menurut waktu. Sebuah serangan
# bisa mengulang fase (pindai ulang setelah masuk), dan urutan fase membantu
# pembaca melihat pola meski timestamp-nya berselang-seling.
PHASES = ["Reconnaissance", "Initial Access", "Execution", "Defense Evasion",
          "Persistence", "Command & Control", "Data Movement"]


def build(result: dict, memory: dict | None = None,
          conversations: list[dict] | None = None) -> dict:
    memory = memory or {}
    conversations = conversations or []
    victim = (result.get("identity") or {}).get("ip")
    attacker = _identify_attacker(result)

    events = []
    events += _first_contact(result, conversations, victim, attacker)
    events += _recon(result, attacker, victim)
    events += _initial_access(result, victim, attacker)
    events += _exploitation(result)
    events += _c2(result, memory, victim)
    events += _persistence(memory)

    events.sort(key=sort_key)
    return {
        "victim": victim,
        "attacker": attacker,
        "events": events,
        "phases": {phase: [e for e in events if e["phase"] == phase] for phase in PHASES},
        "data_movement": _data_movement(conversations, victim, attacker, result),
        "unresolved": _unresolved(events, memory),
    }


def build_from_memory(memory: dict, filename: str = "") -> dict:
    """
    Kronologi dari RAM dump saja, tanpa pcap.

    `CreateTime` tiap proses adalah stempel waktu paling presisi yang tersedia
    di seluruh evidence -- lebih tepat daripada timestamp berkas, yang bisa
    dipalsukan, dan lebih spesifik daripada rentang capture pcap. Mengurutkan
    proses menurut waktu lahirnya memperlihatkan urutan eksekusi apa adanya.
    """
    if not memory or not memory.get("available"):
        return {}
    tree = {t["pid"]: t for t in memory.get("process_tree", [])}
    flagged = _flagged_pids(memory)

    events = []
    for proc in memory.get("processes", []):
        pid = proc.get("PID")
        created = _epoch(proc.get("CreateTime"))
        if created is None or pid not in flagged:
            continue
        node = tree.get(pid, {})
        events.append(_event(
            created, "Execution", node.get("user") or "?",
            f"{proc.get('ImageFileName')} (PID {pid}) mulai berjalan",
            target=node.get("args") or node.get("ancestry"),
            confidence="HIGH",
            query=f"vol -f <dump> windows.pslist --pid {pid}",
            data=f"Induk: {node.get('parent_name') or '(tidak ada di dump)'} "
                 f"(PPID {node.get('ppid')}). Alasan ditandai: "
                 f"{'; '.join(flagged[pid])}"))

    for item in memory.get("lolbin_execution", []):
        node = tree.get(item.get("pid"), {})
        events.append(_event(
            _epoch(node.get("create_time")), "Execution", item.get("user") or "?",
            f"{item['lolbin']} ({item['invocation']}) menjalankan "
            f"{', '.join(item['targets'] or item['unc_paths'])}",
            target=item["args"], confidence="HIGH",
            query=f"vol -f <dump> windows.cmdline --pid {item['pid']}",
            data=f"MITRE {item['mitre_technique']} ({item['mitre_name']})"))

    for share in memory.get("remote_shares", []):
        events.append(_event(
            None, "Initial Access", share["used_by"][0]["process"] if share["used_by"] else "?",
            f"Mengakses share jarak jauh {share['unc_path']}",
            target=f"host {share['host']}, share {share['share']}",
            confidence="HIGH", query="vol -f <dump> windows.cmdline",
            data="Muatan berasal dari luar mesin ini", inferred=True))

    for conn in memory.get("notable_connections", []):
        events.append(_event(
            None, "Command & Control", conn["process"],
            f"Koneksi ke {conn['foreign']} [{conn['state'] or '?'}]",
            target=conn["foreign_ip"], confidence=conn["confidence"],
            query=conn["evidence_query"], data="; ".join(conn["reasons"])))

    for item in memory.get("persistence", []):
        node = tree.get(item.get("pid"), {})
        events.append(_event(
            _epoch(node.get("create_time")), "Persistence",
            node.get("user") or item.get("process"),
            f"{item['binary'] or item['process']} terpasang lewat {item['mechanism']}",
            target=item["path"], confidence="HIGH",
            query=f"vol -f <dump> windows.cmdline --pid {item['pid']}",
            data="Waktu PEMASANGAN tidak terlihat di RAM; yang tercatat hanya waktu "
                 "proses ini mulai berjalan. Untuk waktu pemasangan perlu disk image",
            inferred=True))

    for item in memory.get("process_hollowing", []):
        node = tree.get(item.get("pid"), {})
        events.append(_event(
            _epoch(node.get("create_time")), "Defense Evasion", item.get("user") or "?",
            f"{item['process_name']} melaporkan diri berbeda dari berkas yang "
            f"dijalankannya ({item['commandline_binary']})",
            target=item["args"], confidence="HIGH",
            query=f"vol -f <dump> windows.cmdline --pid {item['pid']}",
            data="Masquerading / process hollowing"))

    for entry in memory.get("code_injection_by_process", []):
        if entry.get("known_false_positive"):
            continue
        node = tree.get(entry.get("pid"), {})
        events.append(_event(
            _epoch(node.get("create_time")), "Defense Evasion", node.get("user") or "?",
            f"{entry['process']} punya {entry['region_count']} region memori "
            "executable+writable",
            target=f"PID {entry['pid']}", confidence="MEDIUM",
            query=f"vol -f <dump> windows.malfind --pid {entry['pid']}",
            data="Region RWX tanpa berkas pendukung di disk"))

    events.sort(key=sort_key)
    # Akun diambil dari windows.getsids, BUKAN dari kolom pelaku: sebagian event
    # berpelaku proses (koneksi jaringan, akses share) dan mencampurnya membuat
    # 'net.exe' dan 'svchost.exe' tampil sebagai nama pengguna.
    accounts = sorted({u for u in (memory.get("users") or {}).values() if u})
    return {
        "source": filename or "RAM dump",
        "victim": None, "attacker": None,
        "events": events,
        "phases": {phase: [e for e in events if e["phase"] == phase] for phase in PHASES},
        "accounts_involved": accounts,
        "data_movement": {"peers": [], "verdict": None},
        "unresolved": [
            "Waktu proses lahir berasal dari RAM; proses yang sudah keluar sebelum "
            "dump diambil tidak muncul sama sekali",
            "Tanpa pcap, isi lalu lintas ke server jarak jauh tidak bisa diperiksa",
            "Tanpa disk image, waktu berkas pertama kali sampai di sistem tidak "
            "bisa dipastikan",
        ],
    }


def _flagged_pids(memory: dict) -> dict:
    """PID yang ditandai modul mana pun, beserta alasannya."""
    flagged: dict[int, list[str]] = {}
    def add(pid, reason):
        if pid is not None:
            flagged.setdefault(pid, []).append(reason)

    for item in memory.get("lolbin_execution", []):
        add(item.get("pid"), f"eksekusi {item['lolbin']}")
    for item in memory.get("suspicious_command_lines", []):
        add(item.get("pid"), "; ".join(item.get("reasons", [])))
    for item in memory.get("process_hollowing", []):
        add(item.get("pid"), "process hollowing")
    for item in memory.get("persistence", []):
        add(item.get("pid"), f"persistence: {item['mechanism']}")
    for entry in memory.get("code_injection_by_process", []):
        if not entry.get("known_false_positive"):
            add(entry.get("pid"), f"malfind {entry['region_count']} region RWX")
    for conn in memory.get("notable_connections", []):
        if conn["confidence"] == "HIGH":
            add(conn.get("pid"), f"koneksi ke {conn['foreign']}")
    return flagged


def _identify_attacker(result: dict) -> str | None:
    """Sumber pemindaian lebih dulu, baru sumber payload serangan."""
    scans = result.get("port_scans") or []
    if scans:
        return max(scans, key=lambda s: s["port_count"])["source_ip"]
    attack = [f["src_ip"] for f in result.get("owasp_findings", [])
              if any(k in f["owasp_category"] for k in ("Injection", "Traversal", "Forgery"))]
    return attack[0] if attack else None


def _event(timestamp, phase, actor, action, target=None, query=None,
           confidence="MEDIUM", data=None, inferred=False):
    return {
        "timestamp": timestamp, "time_utc": to_utc(timestamp) if timestamp else None,
        "phase": phase, "actor": actor, "action": action, "target": target,
        "evidence_query": query, "confidence": confidence, "data": data,
        # Ditandai eksplisit: pembaca laporan harus bisa membedakan apa yang
        # TERLIHAT di paket dari apa yang kita simpulkan dari pola.
        "is_inference": inferred,
    }


def _first_contact(result, conversations, victim, attacker) -> list[dict]:
    if not (victim and attacker):
        return []
    pair = next((c for c in conversations
                 if {c["host_a"], c["host_b"]} == {victim, attacker}), None)
    if not pair or pair.get("first_seen") is None:
        return []
    return [_event(
        pair["first_seen"], "Reconnaissance", attacker,
        f"Kontak pertama dengan {victim}", target=victim,
        query=f"ip.addr=={attacker} && ip.addr=={victim}", confidence="HIGH",
        data=f"Seluruh percakapan: {pair['total_bytes']:,} byte dalam "
             f"{pair['a_to_b_frames'] + pair['b_to_a_frames']:,} paket")]


def _recon(result, attacker, victim) -> list[dict]:
    events = []
    for scan in result.get("port_scans") or []:
        events.append(_event(
            _epoch(scan["window_start_utc"]), "Reconnaissance", scan["source_ip"],
            f"Memindai {scan['port_count']} port dalam {scan['duration_sec']} detik",
            target=victim, query=scan["evidence_query"], confidence="HIGH",
            data=f"{scan['single_touch_ports']} port disentuh sekali — "
                 "pola pemindai otomatis"))
    return events


def _initial_access(result, victim, attacker) -> list[dict]:
    """Sesi masuk BERPAYLOAD ke tiap layanan: di sinilah interaksi sungguhan mulai."""
    events = []
    for service in result.get("exposed_services") or []:
        if not service["sessions_with_payload"]:
            continue
        events.append(_event(
            _epoch(service["first_seen_utc"]), "Initial Access",
            ", ".join(service["distinct_sources"]),
            f"Mengirim {service['sessions_with_payload']} request berisi payload ke "
            f"{service['port']}/tcp ({service['service']})",
            target=f"{victim}:{service['port']}", query=service["evidence_query"],
            confidence="HIGH"))

    # Request HTTP masuk yang benar-benar terbaca isinya -- ini yang bisa dikutip
    # langsung di laporan, bukan sekadar hitungan sesi.
    requests = [s for s in result.get("all_sessions", [])
                if s.get("direction") == "inbound" and s.get("has_payload")]
    for session in requests[:12]:
        events.append(_event(
            session["timestamp"], "Initial Access", session["dst_ip"],
            session["summary"][:180], target=f"{victim}:{session['dst_port']}",
            query=f"tcp.stream=={session['tcp_stream']}", confidence="HIGH"))
    return events


def _exploitation(result) -> list[dict]:
    events = []
    for finding in result.get("owasp_findings") or []:
        events.append(_event(
            finding["timestamp"], "Execution", finding["src_ip"],
            f"{finding['owasp_category']} — hasil: {finding['outcome']}",
            target=f"{finding['dst_ip']} {finding['request_uri'][:80]}",
            query=finding["evidence_query"], confidence=finding["confidence"],
            data=f"Response {finding['response_status']}" if finding.get("response_status") else None))
    return events


def _c2(result, memory, victim) -> list[dict]:
    events = []
    server_processes = ("w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe",
                        "tomcat.exe", "inetinfo.exe", "java.exe", "php-cgi.exe")
    for conn in memory.get("connections", []):
        owner = str(conn.get("Owner") or "").lower()
        if owner not in server_processes or not conn.get("ForeignAddr"):
            continue
        events.append(_event(
            _epoch(conn.get("Created")), "Command & Control", victim,
            f"{conn.get('Owner')} (PID {conn.get('PID')}) membuka koneksi KELUAR ke "
            f"{conn.get('ForeignAddr')}:{conn.get('ForeignPort')}",
            target=conn.get("ForeignAddr"), confidence="HIGH",
            query=f"ip.addr=={conn.get('ForeignAddr')} && tcp.port=={conn.get('ForeignPort')}",
            data="Proses server MENGHUBUNGI klien — pembalikan peran, pola reverse shell"))

    for event in result.get("key_events") or []:
        if event.get("category") == "http_candidate_c2":
            events.append(_event(
                event["timestamp"], "Command & Control", victim,
                f"Lalu lintas HTTP tidak terenkripsi ke {event['destination']}",
                target=event["destination"], query=event.get("evidence_query"),
                confidence=event.get("confidence", "MEDIUM")))
    return events


def _persistence(memory) -> list[dict]:
    events = []
    for item in memory.get("persistence") or []:
        events.append(_event(
            None, "Persistence", item.get("process"),
            f"{item['binary'] or item['process']} dijalankan dari {item['mechanism']}",
            target=item["path"], confidence="HIGH",
            query=f"vol -f <dump> windows.cmdline --pid {item['pid']}",
            data="Waktu pemasangan tidak terlihat di RAM dump — perlu disk image "
                 "(MAC timeline) untuk memastikannya", inferred=True))
    for item in memory.get("process_hollowing") or []:
        events.append(_event(
            None, "Execution", item["process_name"],
            f"Melaporkan diri sebagai {item['process_name']} tapi menjalankan "
            f"{item['commandline_binary']}", target=item["args"][:120],
            confidence="HIGH",
            query=f"vol -f <dump> windows.cmdline --pid {item['pid']}",
            data="Masquerading / process hollowing"))
    return events


def _data_movement(conversations, victim, attacker, result) -> dict:
    """
    Berapa byte ke tiap arah, dan apa artinya.

    Pertanyaan "data apa yang mereka ambil" sering dijawab terbalik. Arah aliran
    byte menentukan ceritanya: data yang KELUAR dari korban berarti pengambilan,
    data yang MASUK berarti pemasangan. Keduanya serius, tapi bukan hal yang sama
    dan tidak boleh tertukar di laporan.
    """
    summary = {"peers": [], "verdict": None, "caveat": None}
    for conv in conversations[:8]:
        peer = conv["host_b"] if conv["host_a"] == victim else conv["host_a"]
        if peer == victim:
            continue
        sent = conv["a_to_b_bytes"] if conv["host_a"] == victim else conv["b_to_a_bytes"]
        received = conv["b_to_a_bytes"] if conv["host_a"] == victim else conv["a_to_b_bytes"]
        summary["peers"].append({
            "peer": peer, "victim_sent_bytes": sent, "victim_received_bytes": received,
            "is_attacker": peer == attacker,
        })

    main = next((p for p in summary["peers"] if p["is_attacker"]), None)
    if not main:
        return summary
    sent, received = main["victim_sent_bytes"], main["victim_received_bytes"]
    if received > sent * 3:
        summary["verdict"] = (
            f"Korban MENERIMA {received:,} byte dari penyerang dan hanya mengirim "
            f"{sent:,} byte. Arah dominan masuk — ini pola PEMASANGAN/pengiriman "
            "berkas, bukan pengambilan data.")
    elif sent > received * 3:
        summary["verdict"] = (
            f"Korban MENGIRIM {sent:,} byte ke penyerang dan hanya menerima "
            f"{received:,} byte. Arah dominan keluar — konsisten dengan pengambilan "
            "data (exfiltration).")
    else:
        summary["verdict"] = (f"Aliran data relatif seimbang ({sent:,} byte keluar, "
                              f"{received:,} byte masuk) — konsisten dengan sesi "
                              "interaktif, bukan transfer berkas besar satu arah.")
    summary["caveat"] = ("Angka ini menghitung SELURUH byte termasuk header dan paket "
                         "pemindaian. Untuk menyimpulkan berkas apa yang berpindah, "
                         "periksa berkas hasil carving dan isi sesi berpayload.")
    return summary


def _unresolved(events, memory) -> list[str]:
    gaps = []
    if not memory:
        gaps.append("Tanpa RAM dump: koneksi tidak bisa dikaitkan ke proses, dan "
                    "persistence tidak terlihat sama sekali")
    if not any(e["phase"] == "Persistence" for e in events):
        gaps.append("Tidak ada mekanisme persistence yang terdeteksi — bisa memang "
                    "tidak ada, bisa juga memakai teknik yang tidak diperiksa "
                    "(registry Run key, WMI subscription, service baru)")
    if any(e["is_inference"] for e in events):
        gaps.append("Beberapa event ditandai sebagai inferensi, bukan pengamatan "
                    "langsung — lihat kolom is_inference")
    gaps.append("Waktu berkas pertama kali sampai di sistem hanya bisa dipastikan "
                "dari disk image (MAC timeline), bukan dari pcap maupun RAM dump")
    return gaps
