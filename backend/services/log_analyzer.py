"""
Analisis berkas log server: Apache/Nginx, IIS W3C, syslog/auth.log, JSON lines.

Log adalah bukti yang paling sering tersedia dan paling jarang dianalisis dengan
benar. Ia menjawab pertanyaan yang tidak bisa dijawab pcap: apa yang terjadi
SEBELUM tangkapan lalu lintas dimulai.

Pola serangan web-nya TIDAK ditulis ulang di sini -- dipakai ulang dari
`owasp_detector`, dan nama temuannya sengaja dibuat sama persis (`owasp_sqli`
dan kawan-kawan) supaya pemetaan MITRE yang sudah ada langsung berlaku tanpa
aturan baru.

Batasnya jujur: log hanya memuat baris request, bukan response body. "Serangan
ini berhasil atau tidak" karena itu hanya bisa disimpulkan sejauh status code
membolehkan -- 403 berarti ditolak, 500 berarti sesuatu pecah, 200 berarti
server menjawab TAPI bukan berarti payload-nya jalan.
"""
import base64
import binascii
import gzip
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus

from .attack_timeline import PHASES, _epoch, _event
from .owasp_detector import OWASP_RULE_MAP
from .reverse_engineer import INTERESTING, _valid_hits
from .timeline_builder import EvidenceLog, sort_key, to_utc
from .tool_fingerprint import classify as classify_agent

# Berkas log bisa berukuran gigabyte. Analisis atas 2 juta baris pertama sudah
# jauh melewati apa yang bisa dibaca manusia; sisanya dilaporkan sebagai
# terpotong, bukan diam-diam dibuang.
MAX_LINES = 2_000_000

# Satu response baru layak disebut perpindahan data kalau ukurannya nyata, bukan
# cuma besar SECARA RELATIF terhadap log yang isinya sedikit.
NOTABLE_TRANSFER_BYTES = 1_048_576

# Nama bulan dipetakan eksplisit, TIDAK lewat %b. strptime("%b") mengikuti locale
# sistem: di Windows berbahasa Indonesia ia menolak "Oct" dan menuntut "Okt",
# sehingga SETIAP timestamp jadi None dan seluruh timeline hilang tanpa satu pun
# pesan error. Bug yang sama pernah terjadi pada capinfos.
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Isi di dalam tanda kutip boleh memuat \" -- User-Agent penyerang sering
# sengaja menyisipkannya untuk memecah parser log.
_Q = r'(?:[^"\\]|\\.)*'

APACHE_RE = re.compile(
    rf'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    rf'"(?P<request>{_Q})"\s+(?P<status>\d{{3}}|-)\s+(?P<bytes>\d+|-)'
    rf'(?:\s+"(?P<referer>{_Q})"\s+"(?P<agent>{_Q})")?')

SYSLOG_RE = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$')

# Peristiwa autentikasi. Urutan penting: "Failed password for invalid user bob"
# cocok dengan dua pola, dan yang lebih spesifik harus menang.
AUTH_PATTERNS = [
    (r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)", "invalid_user"),
    (r"Failed password for (?P<user>\S+) from (?P<ip>\S+)", "failed"),
    (r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", "invalid_user"),
    (r"Accepted (?:password|publickey|keyboard-interactive\S*) for (?P<user>\S+) from (?P<ip>\S+)",
     "success"),
    (r"authentication failure;.*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)", "failed"),
    (r"error: maximum authentication attempts exceeded for (?P<user>\S+) from (?P<ip>\S+)",
     "failed"),
]
AUTH_COMPILED = [(re.compile(p), outcome) for p, outcome in AUTH_PATTERNS]
SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$")

# URI yang menerima kredensial. Dipakai membangun peristiwa autentikasi dari log
# web, sehingga brute force lewat form login terdeteksi oleh kode yang sama
# dengan brute force SSH.
LOGIN_URI = re.compile(
    r"/(wp-login|wp-admin|xmlrpc\.php|admin|login|signin|sign-in|auth|session|"
    r"account/login|user/login|api/(v\d+/)?(login|auth|token)|owa|rdweb)", re.IGNORECASE)

WEB_EXECUTABLE = re.compile(r"\.(php\d?|phtml|asp|aspx|ashx|jsp|jspx|cfm|cgi|pl|py|sh)\b",
                            re.IGNORECASE)
UPLOAD_DIR = re.compile(r"/(upload|uploads|files|images|img|media|tmp|temp|assets|"
                        r"wp-content/uploads|static)/", re.IGNORECASE)
# Nama webshell yang beredar luas. Daftar pendek dengan sengaja: nilai deteksinya
# ada pada "executable di direktori upload", bukan pada menghafal nama berkas.
WEBSHELL_NAMES = re.compile(
    r"/(c99|r57|b374k|wso|alfa|indoxploit|mini|shell|cmd|backdoor|adminer|"
    r"webshell|p0wny|tiny|up|xx)\.(php\d?|asp|aspx|jsp)\b", re.IGNORECASE)


# ---------------------------------------------------------------- pembacaan

def _open(path: Path):
    """Log yang dirotasi hampir selalu ter-gzip. Ekstensinya .1.gz, bukan .gz saja."""
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _apache_time(text: str) -> float | None:
    """`10/Oct/2000:13:55:36 -0700` -> epoch. Offset zona WAJIB dihormati."""
    m = re.match(r"(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})"
                 r"(?:\s+([+-]\d{4}))?", text)
    if not m or m.group(2) not in MONTHS:
        return None
    day, mon, year, hh, mm, ss, off = m.groups()
    try:
        stamp = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                         tzinfo=timezone.utc)
    except ValueError:
        return None
    epoch = stamp.timestamp()
    if off:
        # Log ditulis dalam waktu LOKAL server. Tanpa koreksi ini, timeline log
        # dan timeline pcap (yang selalu UTC) bergeser sejauh offset -- dan
        # korelasi antar keduanya jadi salah tanpa terlihat salah.
        epoch -= (int(off[1:3]) * 3600 + int(off[3:5]) * 60) * (1 if off[0] == "+" else -1)
    return epoch


def _syslog_time(mon: str, day: str, clock: str, year: int) -> float | None:
    if mon not in MONTHS:
        return None
    try:
        return datetime(year, MONTHS[mon], int(day),
                        *(int(x) for x in clock.split(":")),
                        tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _iso_time(text) -> float | None:
    if not text:
        return None
    try:
        cleaned = str(text).replace("Z", "+00:00")
        stamp = datetime.fromisoformat(cleaned)
        return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _split_request(request: str) -> tuple[str, str]:
    """`GET /a?b=1 HTTP/1.1` -> (GET, /a?b=1). Request rusak dikembalikan apa adanya."""
    parts = (request or "").split()
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", request or ""


# ---------------------------------------------------------------- parsing

def detect_format(sample: list[str]) -> str:
    for line in sample:
        if line.startswith("#Fields:"):
            return "iis_w3c"
    scores = Counter()
    for line in sample:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{") and line.endswith("}"):
            scores["json_lines"] += 1
        elif APACHE_RE.match(line):
            scores["apache"] += 1
        elif SYSLOG_RE.match(line):
            scores["syslog"] += 1
    return scores.most_common(1)[0][0] if scores else "unknown"


def parse(path, fallback_year: int | None = None) -> dict:
    """
    Baca log jadi entri ternormalisasi.

    Melaporkan `unparsed` sebagai angka kelas satu. Parser yang mengembalikan
    tiga entri dari berkas 90.000 baris terlihat persis sama dengan log yang
    memang cuma berisi tiga baris -- dan itulah kegagalan diam yang paling mahal
    di seluruh tools ini.
    """
    path = Path(path)
    # Log syslog tidak memuat TAHUN. Tahun diambil dari mtime berkas; kalau
    # hasilnya jatuh di masa depan, berkasnya melewati pergantian tahun dan
    # tahunnya dikurangi satu. Asumsi ini dicatat, bukan disembunyikan.
    year = fallback_year or datetime.fromtimestamp(
        path.stat().st_mtime, tz=timezone.utc).year

    with _open(path) as handle:
        sample = [next(handle, "") for _ in range(200)]
    fmt = detect_format(sample)

    entries: list[dict] = []
    auth: list[dict] = []
    unparsed = 0
    total = 0
    truncated = False
    fields: list[str] = []

    with _open(path) as handle:
        for number, line in enumerate(handle, start=1):
            if number > MAX_LINES:
                truncated = True
                break
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            if line.startswith("#"):
                # Baris header TIDAK dihitung sebagai baris log. Kalau dihitung,
                # berkas IIS berisi 3 request melapor "3 dari 7 baris terbaca"
                # dan terlihat seperti parser yang gagal.
                if line.lower().startswith("#fields:"):
                    # Header bisa muncul BERKALI-KALI dalam satu berkas (IIS
                    # menulisnya ulang tiap restart) dan urutan kolomnya boleh
                    # berubah. Membaca yang pertama saja akan salah kolom.
                    fields = line.split(":", 1)[1].split()
                continue
            total += 1

            entry = (_parse_iis(line, fields) if fmt == "iis_w3c" else
                     _parse_apache(line) if fmt == "apache" else
                     _parse_json(line) if fmt == "json_lines" else
                     None)
            if entry is None and fmt == "syslog":
                event = _parse_syslog(line, year)
                if event:
                    event["line_number"] = number
                    auth.append(event)
                    continue
            if entry is None:
                # Format campuran itu lumrah: satu berkas bisa memuat baris
                # akses dan baris error sekaligus. Baris yang tidak cocok
                # dicoba dengan parser lain sebelum dinyatakan gagal.
                entry = _parse_apache(line)
                if entry is None:
                    event = _parse_syslog(line, year)
                    if event:
                        event["line_number"] = number
                        auth.append(event)
                        continue
            if entry is None:
                unparsed += 1
                continue
            entry["line_number"] = number
            entry["raw"] = line[:500]
            entries.append(entry)

    return {"format": fmt, "entries": entries, "auth_events": auth,
            "lines_total": total, "lines_unparsed": unparsed, "truncated": truncated,
            "assumed_year": year if fmt == "syslog" else None,
            "parse_rate": round(1 - unparsed / total, 4) if total else 0.0}


def _parse_apache(line: str) -> dict | None:
    m = APACHE_RE.match(line)
    if not m:
        return None
    method, uri = _split_request(m.group("request"))
    return {
        "timestamp": _apache_time(m.group("time")),
        "raw_time": m.group("time"),
        "src_ip": m.group("ip"),
        "user": None if m.group("user") in ("-", None) else m.group("user"),
        "method": method, "uri": uri,
        "status": _int(m.group("status")),
        "bytes": _int(m.group("bytes")) or 0,
        "referer": None if m.group("referer") in ("-", None) else m.group("referer"),
        "user_agent": None if m.group("agent") in ("-", None) else m.group("agent"),
    }


def _parse_iis(line: str, fields: list[str]) -> dict | None:
    if not fields:
        return None
    values = line.split()
    if len(values) != len(fields):
        return None
    row = {k: (None if v == "-" else v) for k, v in zip(fields, values)}
    query = row.get("cs-uri-query")
    uri = row.get("cs-uri-stem") or ""
    if query:
        uri = f"{uri}?{query}"
    stamp = _iso_time(f"{row.get('date')}T{row.get('time')}") \
        if row.get("date") and row.get("time") else None
    return {
        "timestamp": stamp,
        "raw_time": f"{row.get('date')} {row.get('time')}",
        # c-ip adalah klien; s-ip adalah server. Tertukar = seluruh laporan
        # menuding server sendiri sebagai penyerang.
        "src_ip": row.get("c-ip") or row.get("s-ip") or "",
        "user": row.get("cs-username"),
        "method": row.get("cs-method") or "",
        "uri": uri,
        "status": _int(row.get("sc-status")),
        "bytes": _int(row.get("sc-bytes")) or 0,
        "referer": row.get("cs(Referer)"),
        # IIS mengganti spasi di User-Agent dengan '+' karena kolomnya
        # dipisah spasi.
        "user_agent": (row.get("cs(User-Agent)") or "").replace("+", " ") or None,
    }


def _parse_json(line: str) -> dict | None:
    try:
        row = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(row, dict):
        return None
    pick = lambda *names: next((row[n] for n in names if row.get(n) not in (None, "")), None)
    uri = pick("uri", "request_uri", "path", "url", "cs-uri-stem") or ""
    request = pick("request", "message")
    method = pick("method", "request_method", "verb")
    if not method and request:
        method, uri = _split_request(str(request))
    return {
        "timestamp": _iso_time(pick("time", "timestamp", "@timestamp", "time_local")),
        "raw_time": str(pick("time", "timestamp", "@timestamp", "time_local") or ""),
        "src_ip": str(pick("remote_addr", "client_ip", "src_ip", "ip", "c-ip") or ""),
        "user": pick("user", "remote_user", "username"),
        "method": str(method or ""), "uri": str(uri),
        "status": _int(pick("status", "status_code", "response_code")),
        "bytes": _int(pick("bytes", "body_bytes_sent", "bytes_sent", "size")) or 0,
        "referer": pick("referer", "referrer", "http_referer"),
        "user_agent": pick("user_agent", "http_user_agent", "agent"),
    }


def _parse_syslog(line: str, year: int) -> dict | None:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    msg, proc = m.group("msg"), m.group("proc")
    stamp = _syslog_time(m.group("mon"), m.group("day"), m.group("time"), year)
    base = {"timestamp": stamp, "time_utc": to_utc(stamp), "host": m.group("host"),
            "service": proc, "raw": line[:500]}

    for pattern, outcome in AUTH_COMPILED:
        hit = pattern.search(msg)
        if hit:
            return {**base, "outcome": outcome,
                    "user": hit.groupdict().get("user"),
                    "src_ip": hit.groupdict().get("ip") or ""}
    if proc == "sudo":
        hit = SUDO_RE.match(msg)
        if hit:
            return {**base, "outcome": "sudo", "src_ip": "",
                    "user": hit.group("user"), "command": hit.group("command")}
    return None


# ---------------------------------------------------------------- deteksi

def _query(path_name: str, needle: str) -> str:
    """
    Padanan filter Wireshark untuk log: perintah yang menghasilkan baris itu.

    Setiap temuan harus bisa diverifikasi ulang oleh pembaca laporan tanpa
    menjalankan tools ini.

    `-F` wajib. URI serangan penuh karakter yang bermakna di regex -- `.`, `?`,
    `*`, `[`, `+` -- dan tanpa -F perintah yang kita cetak sebagai bukti bisa
    tidak menemukan barisnya sendiri, atau malah gagal dengan error regex.
    """
    return f'grep -nF "{needle.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}" ' \
           f'{path_name}'


def detect_web_attacks(entries: list[dict], name: str, evidence: EvidenceLog) -> list[dict]:
    """Pola OWASP pada URI. Aturannya dipakai ulang dari `owasp_detector`."""
    findings = []
    for entry in entries:
        # unquote_plus, BUKAN unquote. Query string meng-encode spasi sebagai
        # '+', dan IIS melakukannya untuk seluruh baris. Dengan unquote biasa,
        # "1'+OR+'1'='1" tidak pernah cocok dengan pola SQLi mana pun -- karena
        # semua pola itu menuntut spasi. Setiap serangan SQLi di log IIS lolos
        # tanpa satu pun tanda bahwa ada yang terlewat.
        decoded = unquote_plus(entry["uri"])
        for category, (patterns, finding_type) in OWASP_RULE_MAP.items():
            matched = next((p for p in patterns if re.search(p, decoded, re.IGNORECASE)), None)
            if not matched:
                continue
            status = entry["status"]
            # Tanpa response body, "leaked" dan "reflected" TIDAK bisa
            # disimpulkan. Melaporkannya berdasar status 200 saja akan menaikkan
            # tiap kecocokan regex jadi confidence HIGH -- pabrik false positive.
            outcome = ("blocked" if status in (403, 406) else
                       "error" if status and 500 <= status < 600 else
                       "not_found" if status == 404 else
                       "server_answered" if status and 200 <= status < 400 else
                       "unknown")
            query = _query(name, entry["uri"][:60])
            findings.append({
                "timestamp": entry["timestamp"], "time_utc": to_utc(entry["timestamp"]),
                "line_number": entry["line_number"],
                "src_ip": entry["src_ip"], "owasp_category": category,
                "matched_pattern": matched, "http_method": entry["method"],
                "request_uri": entry["uri"][:300], "request_snippet": decoded[:300],
                "response_status": status, "response_bytes": entry["bytes"],
                "outcome": outcome,
                "confidence": "HIGH" if outcome == "error" else "MEDIUM",
                "user_agent": entry["user_agent"], "evidence_query": query,
            })
            evidence.track(finding_type, query, f"{category} dari {entry['src_ip']}",
                           note=f"Baris {entry['line_number']}. Status {status}, "
                                f"{entry['bytes']} byte terkirim. Outcome: {outcome}. "
                                "Log tidak memuat response body, jadi keberhasilan "
                                "eksploitasi TIDAK bisa dipastikan dari sini -- "
                                "periksa log aplikasi atau basis data.")
    return findings


def detect_scanners(entries: list[dict], name: str, evidence: EvidenceLog) -> list[dict]:
    """Perkakas dari User-Agent + enumerasi dari rasio 404 per sumber."""
    by_ip: dict[str, dict] = {}
    for entry in entries:
        ip = entry["src_ip"]
        if not ip:
            continue
        stat = by_ip.setdefault(ip, {"src_ip": ip, "requests": 0, "not_found": 0,
                                     "agents": Counter(), "first": None, "last": None,
                                     "uris": set(), "statuses": Counter()})
        stat["requests"] += 1
        stat["statuses"][entry["status"]] += 1
        if entry["status"] == 404:
            stat["not_found"] += 1
        if entry["user_agent"]:
            stat["agents"][entry["user_agent"]] += 1
        stat["uris"].add(entry["uri"].split("?")[0])
        ts = entry["timestamp"]
        if ts is not None:
            stat["first"] = ts if stat["first"] is None else min(stat["first"], ts)
            stat["last"] = ts if stat["last"] is None else max(stat["last"], ts)

    results = []
    for stat in by_ip.values():
        # SEMUA perkakas per sumber, bukan yang User-Agent-nya paling sering.
        # Satu penyerang lazim memakai beberapa alat berurutan; melaporkan yang
        # terbanyak saja menampilkan "Nikto" dan menyembunyikan sqlmap yang
        # dipakai sesudahnya -- justru temuan yang lebih berat.
        tools: dict[str, dict] = {}
        for agent, count in stat["agents"].most_common():
            info = classify_agent(agent)
            if not info["tool"]:
                continue
            row = tools.setdefault(info["tool"], {**info, "requests": 0, "user_agent": agent})
            row["requests"] += count
        attack_tools = [t for t in tools.values() if t["is_attack_tool"]]
        primary = max(attack_tools or tools.values() or [{}],
                      key=lambda t: t.get("requests", 0))
        ratio = stat["not_found"] / stat["requests"] if stat["requests"] else 0
        # Ambang: minimal 20 request DAN mayoritas 404. Menebak nama direktori
        # adalah pemindaian; satu-dua 404 adalah pemakaian normal.
        enumerating = stat["requests"] >= 20 and ratio >= 0.5 and len(stat["uris"]) >= 20
        if not attack_tools and not enumerating:
            continue
        span = (stat["last"] - stat["first"]) if stat["first"] and stat["last"] else 0
        record = {
            "src_ip": stat["src_ip"], "requests": stat["requests"],
            "not_found": stat["not_found"], "not_found_ratio": round(ratio, 3),
            "unique_paths": len(stat["uris"]),
            "user_agent": primary.get("user_agent"),
            "tool": primary.get("tool"), "tool_category": primary.get("category"),
            "tools": [{"tool": t["tool"], "category": t["category"],
                       "requests": t["requests"], "user_agent": t["user_agent"]}
                      for t in sorted(tools.values(), key=lambda t: -t["requests"])],
            "is_enumeration": enumerating,
            "first_seen": to_utc(stat["first"]), "last_seen": to_utc(stat["last"]),
            "duration_sec": round(span, 1),
            "requests_per_min": round(stat["requests"] / (span / 60), 1) if span > 60 else None,
            "evidence_query": _query(name, stat["src_ip"]),
        }
        results.append(record)
        for tool in attack_tools:
            evidence.track("attack_tool_identified", record["evidence_query"],
                           f"{tool['tool']} ({tool['category']}) dari {stat['src_ip']}",
                           note=f"User-Agent: {tool['user_agent']}. {tool['requests']} request. "
                                "User-Agent mudah dipalsukan -- ini menunjukkan perkakas "
                                "dengan setelan bawaan, bukan bukti mutlak.")
        if enumerating:
            evidence.track("log_enumeration", record["evidence_query"],
                           f"{stat['src_ip']} menebak {len(stat['uris'])} path",
                           note=f"{stat['not_found']} dari {stat['requests']} request "
                                f"berakhir 404 ({ratio:.0%}). Pola menebak nama direktori "
                                "atau berkas, bukan penjelajahan biasa.")
    return sorted(results, key=lambda r: -r["requests"])


def _web_auth_events(entries: list[dict]) -> list[dict]:
    """
    Percobaan login dari log web, dibentuk sama seperti peristiwa auth syslog.

    Dengan begini brute force lewat form login diperiksa kode yang sama dengan
    brute force SSH -- bukan dua implementasi yang harus dijaga sinkron.
    """
    events = []
    for entry in entries:
        if entry["method"] not in ("POST", "GET") or not LOGIN_URI.search(entry["uri"]):
            continue
        status = entry["status"]
        if entry["method"] == "GET" and status not in (401, 403):
            continue      # membuka halaman login bukan percobaan login
        events.append({
            "timestamp": entry["timestamp"], "time_utc": to_utc(entry["timestamp"]),
            "src_ip": entry["src_ip"], "user": entry["user"],
            "service": "http", "line_number": entry["line_number"],
            "outcome": ("failed" if status in (401, 403) else
                        "success" if status and status in (200, 301, 302) else "unknown"),
            "raw": entry.get("raw", ""),
        })
    return events


def detect_brute_force(auth_events: list[dict], name: str, evidence: EvidenceLog,
                       threshold: int = 10) -> list[dict]:
    """
    Kegagalan berulang per sumber, dan yang paling penting: keberhasilan SETELAHNYA.

    Menghitung kegagalan saja menjawab "ada yang mencoba". Yang ditanyakan
    penyelidikan adalah "ada yang berhasil masuk" -- dan itu hanya terlihat
    kalau peristiwa sukses dicocokkan dengan urutan waktunya terhadap kegagalan.
    """
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for event in auth_events:
        if event.get("src_ip") and event.get("outcome") in ("failed", "invalid_user",
                                                            "success"):
            by_ip[event["src_ip"]].append(event)

    results = []
    for ip, events in by_ip.items():
        events.sort(key=sort_key)
        failures = [e for e in events if e["outcome"] in ("failed", "invalid_user")]
        successes = [e for e in events if e["outcome"] == "success"]
        if len(failures) < threshold:
            continue
        first_fail = failures[0]["timestamp"]
        # Sukses yang dihitung hanya yang terjadi SETELAH kegagalan pertama.
        # Login sah pagi hari lalu brute force sore hari bukan "kredensial
        # berhasil ditebak".
        breached = [s for s in successes
                    if s["timestamp"] and first_fail and s["timestamp"] >= first_fail]
        span = ((failures[-1]["timestamp"] - first_fail)
                if failures[-1]["timestamp"] and first_fail else 0)
        users = Counter(e["user"] for e in failures if e["user"])
        record = {
            "src_ip": ip, "failures": len(failures), "successes": len(successes),
            "compromised": bool(breached),
            "compromised_accounts": sorted({s["user"] for s in breached if s["user"]}),
            "first_attempt": to_utc(first_fail),
            "last_attempt": to_utc(failures[-1]["timestamp"]),
            "success_at": to_utc(breached[0]["timestamp"]) if breached else None,
            "duration_sec": round(span, 1),
            "attempts_per_min": round(len(failures) / (span / 60), 1) if span > 60 else None,
            "targeted_users": [u for u, _ in users.most_common(10)],
            "services": sorted({e.get("service") or "?" for e in events}),
            "confidence": "HIGH" if breached else "MEDIUM",
            "evidence_query": _query(name, ip),
        }
        results.append(record)
        evidence.track("log_brute_force", record["evidence_query"],
                       f"{len(failures)} kegagalan autentikasi dari {ip}",
                       note=f"Menyasar {', '.join(record['targeted_users'][:5]) or '?'} "
                            f"selama {span:.0f} detik lewat "
                            f"{', '.join(record['services'])}.")
        if breached:
            evidence.track("log_bruteforce_success", record["evidence_query"],
                           f"{ip} berhasil masuk sebagai "
                           f"{', '.join(record['compromised_accounts']) or '(user tidak tercatat)'}",
                           note=f"Login berhasil pada {record['success_at']}, setelah "
                                f"{len(failures)} kegagalan sejak {record['first_attempt']}. "
                                "Ini indikator kompromi kredensial paling langsung yang "
                                "bisa diberikan sebuah log. Periksa apa yang dilakukan "
                                "akun itu SETELAH waktu tersebut.")
    return sorted(results, key=lambda r: (not r["compromised"], -r["failures"]))


# Perintah yang mengunduh lalu menjalankan, atau memasang akses tetap. Ini yang
# lazim dijalankan tepat setelah kredensial berhasil ditebak.
RISKY_COMMAND = [
    (r"(curl|wget)[^|]*\|\s*(ba)?sh", "mengunduh skrip lalu langsung menjalankannya"),
    (r"(curl|wget)\s+.*(-O|-o|--output)", "mengunduh berkas ke server"),
    (r"chmod\s+[0-7]*7[0-7]*\s", "memberi izin eksekusi"),
    (r"(nc|ncat|netcat|socat)\s+.*(-e|-c|exec)", "membuka reverse shell"),
    (r"(useradd|adduser|usermod\s+-aG|passwd\s+\w)", "mengubah akun pengguna"),
    (r"authorized_keys", "menanam kunci SSH untuk akses tetap"),
    (r"(crontab|systemctl\s+enable|/etc/rc\.local|/etc/cron)", "memasang persistence"),
    (r"(history\s+-c|rm\s+.*\.bash_history|shred|/var/log)", "menghapus jejak"),
    (r"base64\s+-d|echo\s+[A-Za-z0-9+/=]{40,}\s*\|", "perintah tersamar base64"),
]


def detect_privilege_use(auth_events: list[dict], brute: list[dict], name: str,
                         evidence: EvidenceLog) -> list[dict]:
    """
    Perintah sudo, dan yang paling penting: yang dijalankan SETELAH login paksa berhasil.

    "Siapa berhasil masuk" hanya separuh jawaban. Yang menentukan tingkat
    kerusakan adalah apa yang dikerjakan akun itu sesudahnya -- dan jejaknya ada
    di baris sudo yang selama ini terbaca lalu dibuang.
    """
    breach_times = [_epoch(b["success_at"]) for b in brute
                    if b["compromised"] and b["success_at"]]
    earliest = min(breach_times) if breach_times else None
    breached_users = {u for b in brute for u in b["compromised_accounts"]}

    results = []
    for event in auth_events:
        if event.get("outcome") != "sudo":
            continue
        command = event.get("command") or ""
        reasons = [why for pattern, why in RISKY_COMMAND
                   if re.search(pattern, command, re.IGNORECASE)]
        after_breach = bool(earliest and event["timestamp"] and event["timestamp"] >= earliest)
        by_breached = event.get("user") in breached_users
        if not (reasons or after_breach or by_breached):
            continue
        confidence = "HIGH" if (reasons and (after_breach or by_breached)) else \
                     "MEDIUM" if reasons or by_breached else "LOW"
        record = {
            "timestamp": event["timestamp"], "time_utc": event.get("time_utc"),
            "line_number": event.get("line_number"), "user": event.get("user"),
            "command": command[:300], "reasons": reasons,
            "after_breach": after_breach, "by_compromised_account": by_breached,
            "confidence": confidence,
            "evidence_query": _query(name, command[:60]),
        }
        results.append(record)
        evidence.track("log_privilege_use", record["evidence_query"],
                       f"sudo oleh {event.get('user')}: {command[:80]}",
                       note=("Dijalankan SETELAH login paksa berhasil. " if after_breach else "")
                            + ("Oleh akun yang kredensialnya jebol. " if by_breached else "")
                            + ("; ".join(reasons) or "Perintah tidak tampak berbahaya, "
                               "dicatat karena konteks waktunya."))
    return sorted(results, key=lambda r: sort_key(r))


def detect_webshell(entries: list[dict], name: str, evidence: EvidenceLog) -> list[dict]:
    """
    Berkas yang dapat dieksekusi di direktori unggahan, atau nama webshell umum.

    Direktori unggahan dirancang menerima berkas dari pengguna dan TIDAK
    seharusnya mengeksekusi apa pun. Satu request 200 ke .php di sana adalah
    salah satu sinyal paling kuat yang bisa muncul di log web.
    """
    hits: dict[str, dict] = {}
    for entry in entries:
        uri = entry["uri"]
        path_only = uri.split("?")[0]
        known = bool(WEBSHELL_NAMES.search(path_only))
        in_upload = bool(UPLOAD_DIR.search(path_only) and WEB_EXECUTABLE.search(path_only))
        if not (known or in_upload):
            continue
        record = hits.setdefault(path_only, {
            "uri": path_only, "requests": 0, "sources": Counter(), "methods": Counter(),
            "statuses": Counter(), "bytes_total": 0, "first": None, "last": None,
            "reason": "nama webshell yang dikenal" if known
                      else "berkas dapat dieksekusi di direktori unggahan",
            "confidence": "HIGH" if known else "MEDIUM",
        })
        record["requests"] += 1
        record["sources"][entry["src_ip"]] += 1
        record["methods"][entry["method"]] += 1
        record["statuses"][entry["status"]] += 1
        record["bytes_total"] += entry["bytes"]
        ts = entry["timestamp"]
        if ts is not None:
            record["first"] = ts if record["first"] is None else min(record["first"], ts)
            record["last"] = ts if record["last"] is None else max(record["last"], ts)

    results = []
    for record in hits.values():
        answered = any(s and 200 <= s < 300 for s in record["statuses"])
        record = {**record,
                  "sources": [ip for ip, _ in record["sources"].most_common()],
                  "methods": [m for m, _ in record["methods"].most_common()],
                  "statuses": {str(k): v for k, v in record["statuses"].items()},
                  "server_answered": answered,
                  "first_seen": to_utc(record.pop("first")),
                  "last_seen": to_utc(record.pop("last")),
                  "evidence_query": _query(name, record["uri"][:60])}
        if answered:
            record["confidence"] = "HIGH"
        results.append(record)
        evidence.track("log_webshell_access", record["evidence_query"], record["uri"],
                       note=f"{record['requests']} request dari "
                            f"{', '.join(record['sources'][:3])}, status "
                            f"{record['statuses']}, {record['bytes_total']} byte terkirim. "
                            f"{record['reason']}. "
                            + ("Server MENJAWAB 2xx — berkasnya ada dan dieksekusi."
                               if answered else "Server tidak pernah menjawab 2xx."))
    return sorted(results, key=lambda r: -r["requests"])


# Kandidat base64 di dalam nilai parameter. Minimal 16 karakter: di bawah itu
# kata biasa seperti "administrator" ikut cocok dan hasilnya jadi sampah.
B64_VALUE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
# Parameter yang memang WAJAR berisi blob panjang. Bukan untuk membuang temuan,
# hanya menurunkan confidence -- sesi yang di-encode dan muatan yang di-encode
# terlihat sama persis dari luar.
BENIGN_PARAM = re.compile(r"^(sig|signature|token|jwt|state|nonce|csrf|hash|"
                          r"session|sid|sess|auth|bearer|utm_\w+|gclid|fbclid|"
                          r"_ga|cache|v|ver|hmac|checksum|etag)$", re.IGNORECASE)


def detect_encoded_parameters(entries: list[dict], name: str,
                              evidence: EvidenceLog) -> list[dict]:
    """
    Nilai parameter yang ternyata base64 dan terdekode jadi teks terbaca.

    Muatan yang di-encode di query string adalah cara paling murah menyelundupkan
    perintah, data curian, atau tugas C2 lewat log yang dipantau: yang tercatat
    hanya deretan huruf tanpa arti, dan pembaca melewatinya begitu saja.

    Dilaporkan berdasarkan HASIL DEKODENYA, bukan sekadar "ini terlihat base64".
    Token sesi dan JWT juga base64 -- bedanya, yang itu terdekode jadi byte acak,
    bukan kalimat.
    """
    results = []
    for entry in entries:
        query = entry["uri"].partition("?")[2]
        if not query:
            continue
        for pair in re.split(r"[&;]", query):
            key, _, raw = pair.partition("=")
            value = unquote_plus(raw)
            if not B64_VALUE.match(value):
                continue
            try:
                decoded = base64.b64decode(value.replace("-", "+").replace("_", "/")
                                           + "=" * (-len(value) % 4), validate=True)
            except (ValueError, binascii.Error):
                continue
            if len(decoded) < 6:
                continue
            text = decoded.decode("utf-8", "replace")
            # Byte acak yang kebetulan valid base64 (token, hash, kunci) terdekode
            # jadi sampah. Yang menarik justru yang terdekode jadi teks -- itu
            # berarti seseorang memang menuliskan sesuatu di sana.
            printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
            if printable / len(text) < 0.9:
                continue
            iocs = _valid_hits(INTERESTING.findall(decoded))
            benign_name = bool(BENIGN_PARAM.match(key))
            confidence = "HIGH" if iocs else ("LOW" if benign_name else "MEDIUM")
            record = {
                "timestamp": entry["timestamp"], "time_utc": to_utc(entry["timestamp"]),
                "line_number": entry["line_number"], "src_ip": entry["src_ip"],
                "uri": entry["uri"][:200], "parameter": key,
                "encoded": value[:200], "decoded": text[:300],
                "iocs": iocs, "status": entry["status"],
                "common_token_name": benign_name, "confidence": confidence,
                "evidence_query": _query(name, value[:60]),
            }
            results.append(record)
            evidence.track("log_encoded_parameter", record["evidence_query"],
                           f"{key}= terdekode menjadi: {text[:120]}",
                           note=f"Baris {entry['line_number']}, dari {entry['src_ip']}, "
                                f"status {entry['status']}. "
                                + (f"Isi dekodenya memuat {', '.join(iocs[:4])}. " if iocs else "")
                                + ("Nama parameternya lazim dipakai token sesi, jadi ini "
                                   "bisa saja sah. " if benign_name else "")
                                + "Base64 di query string tidak selalu jahat — tapi ia "
                                  "membuat isi request tidak terbaca di log, dan itu "
                                  "berlaku baik disengaja maupun tidak.")
    return results


def detect_large_transfers(entries: list[dict], name: str, evidence: EvidenceLog,
                           top: int = 10) -> list[dict]:
    """
    Response terbesar. Bukan temuan sendiri -- penunjuk ke mana harus melihat.

    Data yang keluar dari aplikasi web keluar sebagai response, dan satu-satunya
    jejaknya di log adalah kolom ukuran.
    """
    served = [e for e in entries if e["bytes"] and e["status"] and 200 <= e["status"] < 300]
    if not served:
        return []
    total = sum(e["bytes"] for e in served)
    biggest = sorted(served, key=lambda e: -e["bytes"])[:top]
    results = []
    for entry in biggest:
        share = entry["bytes"] / total if total else 0
        results.append({
            "timestamp": entry["timestamp"], "time_utc": to_utc(entry["timestamp"]),
            "line_number": entry["line_number"], "src_ip": entry["src_ip"],
            "uri": entry["uri"][:200], "bytes": entry["bytes"],
            "share_of_total": round(share, 4), "status": entry["status"],
            "evidence_query": _query(name, entry["uri"][:60]),
        })
    # Porsi saja TIDAK cukup. Di log berisi 6 baris, logo.png 4 KB menguasai 53%
    # seluruh byte dan naik jadi temuan "data keluar" -- padahal itu logo. Batas
    # absolut harus ikut terpenuhi supaya persentase pada log kecil tidak jadi
    # temuan palsu. Sepuluh terbesar tetap didaftarkan sebagai rujukan.
    for item in results:
        item["is_notable"] = (item["share_of_total"] >= 0.25
                              and item["bytes"] >= NOTABLE_TRANSFER_BYTES)
        if item["is_notable"]:
            evidence.track("log_large_response", item["evidence_query"],
                           f"{item['bytes']} byte ke {item['src_ip']}",
                           note=f"Satu response ini {item['share_of_total']:.0%} dari "
                                f"seluruh {total} byte yang dilayani. URI: {item['uri']}. "
                                "Periksa apakah berkas ini memang boleh diunduh.")
    return results


def summarize(parsed: dict, entries: list[dict]) -> dict:
    statuses = Counter(e["status"] for e in entries if e["status"])
    times = [e["timestamp"] for e in entries if e["timestamp"] is not None]
    times += [e["timestamp"] for e in parsed["auth_events"] if e.get("timestamp")]
    return {
        "format": parsed["format"],
        # Berapa baris yang benar-benar request web. auth.log tidak punya satu
        # pun, dan statistik status/byte/path untuknya nol semua -- angka nol
        # yang dicetak sebagai temuan terbaca seolah "tidak ada error", padahal
        # artinya "pertanyaannya tidak berlaku untuk berkas ini".
        "web_entries": len(entries),
        "lines_total": parsed["lines_total"],
        "lines_parsed": len(entries) + len(parsed["auth_events"]),
        "lines_unparsed": parsed["lines_unparsed"],
        "parse_rate": parsed["parse_rate"],
        "truncated": parsed["truncated"],
        "assumed_year": parsed["assumed_year"],
        "unique_sources": len({e["src_ip"] for e in entries if e["src_ip"]}
                              | {e["src_ip"] for e in parsed["auth_events"] if e.get("src_ip")}),
        "unique_paths": len({e["uri"].split("?")[0] for e in entries}),
        "bytes_served": sum(e["bytes"] for e in entries),
        "by_status": {str(k): v for k, v in statuses.most_common()},
        "error_rate": round(sum(v for k, v in statuses.items() if k >= 400)
                            / sum(statuses.values()), 4) if statuses else 0.0,
        "first_event": to_utc(min(times)) if times else None,
        "last_event": to_utc(max(times)) if times else None,
    }


def build_timeline(attacks, scanners, brute, privilege, webshells, encoded,
                   transfers, stats) -> dict:
    """
    Kronologi dalam bentuk yang SAMA dengan `attack_timeline`.

    Bentuknya dipakai ulang, bukan ditiru: pencetak laporan dan tampilan GUI
    untuk kronologi sudah ada dan sudah teruji. Bentuk sendiri berarti keduanya
    harus ditulis dua kali dan dijaga tetap sinkron.
    """
    events = []
    for item in scanners:
        tools = ", ".join(t["tool"] for t in item.get("tools", []) if t["tool"])
        events.append(_event(
            _epoch(item["first_seen"]), "Reconnaissance", item["src_ip"],
            f"Memindai dengan {tools or 'perkakas tidak dikenal'}",
            target=f"{item['unique_paths']} path unik, {item['not_found']} berakhir 404",
            query=item["evidence_query"], confidence="MEDIUM",
            data=f"{item['requests']} request selama {item['duration_sec']:.0f} detik"
                 + (f" ({item['requests_per_min']}/menit)" if item["requests_per_min"] else ""),
            # Perkakas disimpulkan dari User-Agent, yang bisa dipalsukan siapa saja.
            inferred=True))
    for item in attacks:
        events.append(_event(
            item["timestamp"], "Initial Access", item["src_ip"],
            item["owasp_category"], target=item["request_uri"][:120],
            query=item["evidence_query"], confidence=item["confidence"],
            data=f"Server menjawab {item['response_status']} "
                 f"({item['outcome']}), {item['response_bytes']} byte"))
    for item in brute:
        events.append(_event(
            _epoch(item["first_attempt"]), "Initial Access", item["src_ip"],
            f"{item['failures']} percobaan autentikasi gagal",
            target=", ".join(item["targeted_users"][:5]) or "(user tidak tercatat di log)",
            query=item["evidence_query"], confidence="MEDIUM",
            data=f"lewat {', '.join(item['services'])} selama "
                 f"{item['duration_sec']:.0f} detik"))
        if item["compromised"]:
            events.append(_event(
                _epoch(item["success_at"]), "Initial Access", item["src_ip"],
                "LOGIN BERHASIL setelah rentetan kegagalan",
                target=", ".join(item["compromised_accounts"]) or "(user tidak tercatat di log)",
                query=item["evidence_query"], confidence="HIGH",
                data="Indikator kompromi kredensial paling langsung yang bisa "
                     "diberikan sebuah log."))
    for item in privilege:
        events.append(_event(
            item["timestamp"],
            "Persistence" if any("persistence" in r or "kunci SSH" in r
                                 for r in item["reasons"]) else "Execution",
            item["user"], "Menjalankan perintah lewat sudo",
            target=item["command"][:120], query=item["evidence_query"],
            confidence=item["confidence"],
            data="; ".join(item["reasons"]) or None))
    for item in webshells:
        events.append(_event(
            _epoch(item["first_seen"]),
            "Persistence" if item["server_answered"] else "Initial Access",
            ", ".join(item["sources"][:3]), f"Akses {item['uri']}",
            target=item["reason"], query=item["evidence_query"],
            confidence=item["confidence"],
            data=f"{item['requests']} request, status {item['statuses']}, "
                 f"{item['bytes_total']} byte terkirim"))
    for item in encoded:
        if item["confidence"] == "LOW":
            continue
        events.append(_event(
            item["timestamp"], "Data Movement" if item["iocs"] else "Execution",
            item["src_ip"], f"Parameter ter-encode: {item['parameter']}=",
            target=item["decoded"][:120], query=item["evidence_query"],
            confidence=item["confidence"],
            data=(f"Isi dekodenya memuat {', '.join(item['iocs'][:4])}. " if item["iocs"] else "")
                 + f"Server menjawab {item['status']}.",
            # Bahwa nilainya base64 itu fakta; bahwa isinya disembunyikan
            # dengan sengaja adalah kesimpulan.
            inferred=True))
    for item in transfers:
        if not item["is_notable"]:
            continue
        events.append(_event(
            item["timestamp"], "Data Movement", item["src_ip"],
            f"Mengunduh {item['bytes']} byte", target=item["uri"][:120],
            query=item["evidence_query"], confidence="MEDIUM",
            data=f"{item['share_of_total']:.0%} dari seluruh byte yang dilayani "
                 "dalam log ini"))

    events.sort(key=sort_key)
    attackers = Counter(e["actor"] for e in events
                        if e["phase"] in ("Reconnaissance", "Initial Access") and e["actor"])
    return {
        "victim": None,
        "attacker": attackers.most_common(1)[0][0] if attackers else None,
        "events": events,
        "phases": {phase: [e for e in events if e["phase"] == phase] for phase in PHASES},
        "data_movement": [e for e in events if e["phase"] == "Data Movement"],
        "unresolved": _gaps(events, stats),
    }


def _gaps(events: list[dict], stats: dict) -> list[str]:
    """
    Apa yang log ini TIDAK bisa jawab.

    Laporan yang diam soal batasnya membuat pembaca memperlakukan "tidak ada
    temuan" sebagai "tidak terjadi apa-apa".
    """
    gaps = []
    if stats["web_entries"]:
        gaps.append("Log akses hanya memuat baris request. Isi response tidak ada di "
                    "sini, jadi apakah payload benar-benar dieksekusi harus dipastikan "
                    "dari log aplikasi, log basis data, atau berkas di server.")
        if not any(e["phase"] == "Data Movement" for e in events):
            gaps.append("Tidak ada satu response pun yang ukurannya menonjol. Kalau data "
                        "memang keluar, ia keluar sedikit-sedikit atau lewat jalur lain.")
    if stats["parse_rate"] < 0.5:
        gaps.append(f"Hanya {stats['parse_rate']:.0%} baris yang terbaca "
                    f"({stats['lines_unparsed']} gagal). Temuan di atas tidak "
                    "meliputi seluruh isi berkas.")
    if stats["truncated"]:
        gaps.append(f"Berkas dipotong di {stats['lines_total']} baris.")
    if stats["assumed_year"]:
        gaps.append(f"Format syslog tidak memuat tahun; {stats['assumed_year']} "
                    "diambil dari waktu modifikasi berkas.")
    if any(e["is_inference"] for e in events):
        gaps.append("Sebagian event ditandai [inferensi] -- disimpulkan dari pola atau "
                    "User-Agent, bukan terlihat langsung.")
    return gaps


def analyze(path, evidence: EvidenceLog | None = None) -> dict:
    if evidence is None:
        evidence = EvidenceLog()
    path = Path(path)
    name = path.name

    parsed = parse(path)
    entries = parsed["entries"]
    auth_events = parsed["auth_events"] + _web_auth_events(entries)

    attacks = detect_web_attacks(entries, name, evidence)
    scanners = detect_scanners(entries, name, evidence)
    brute = detect_brute_force(auth_events, name, evidence)
    # Sesudah brute force: perintah pasca-masuk hanya bisa dinilai kalau sudah
    # diketahui kapan dan siapa yang jebol.
    privilege = detect_privilege_use(auth_events, brute, name, evidence)
    webshells = detect_webshell(entries, name, evidence)
    encoded = detect_encoded_parameters(entries, name, evidence)
    transfers = detect_large_transfers(entries, name, evidence)
    stats = summarize(parsed, entries)

    # Parser yang gagal atas mayoritas baris HARUS mengatakannya. Tanpa ini,
    # "0 temuan" dari log yang formatnya tidak dikenali terlihat persis sama
    # dengan "0 temuan" dari log yang memang bersih.
    if stats["lines_total"] and stats["parse_rate"] < 0.5:
        evidence.track("log_parse_incomplete", f"wc -l {name}",
                       f"hanya {stats['parse_rate']:.0%} baris terbaca",
                       note=f"Format terdeteksi: {parsed['format']}. "
                            f"{stats['lines_unparsed']} dari {stats['lines_total']} baris "
                            "tidak cocok dengan format mana pun yang dikenali. Temuan di "
                            "bawah ini TIDAK meliputi seluruh isi berkas.")
    if parsed["assumed_year"]:
        evidence.track("log_year_assumed", f"stat {name}", str(parsed["assumed_year"]),
                       note="Format syslog tidak memuat tahun. Tahun diambil dari waktu "
                            "modifikasi berkas. Kalau berkas ini disalin ulang, tahunnya "
                            "bisa salah — cocokkan dengan sumber lain sebelum dipakai "
                            "di timeline gabungan.")

    return {
        "available": True,
        "summary": stats,
        "web_attacks": attacks,
        "attack_summary": _by_category(attacks),
        "scanners": scanners,
        "brute_force": brute,
        "privilege_use": privilege,
        "webshells": webshells,
        "encoded_parameters": encoded,
        "large_transfers": transfers,
        "auth_events": [e for e in auth_events if e.get("outcome") != "unknown"][:500],
        "top_sources": _top_sources(entries),
        "timeline": build_timeline(attacks, scanners, brute, privilege, webshells,
                                   encoded, transfers, stats),
    }


def _by_category(attacks: list[dict]) -> dict:
    categories = Counter(a["owasp_category"] for a in attacks)
    return {"total": len(attacks),
            "by_category": dict(categories),
            "by_outcome": dict(Counter(a["outcome"] for a in attacks)),
            "attackers": sorted({a["src_ip"] for a in attacks})}


def _top_sources(entries: list[dict], top: int = 15) -> list[dict]:
    stats: dict[str, dict] = {}
    for entry in entries:
        if not entry["src_ip"]:
            continue
        row = stats.setdefault(entry["src_ip"], {"src_ip": entry["src_ip"], "requests": 0,
                                                 "bytes": 0, "errors": 0})
        row["requests"] += 1
        row["bytes"] += entry["bytes"]
        if entry["status"] and entry["status"] >= 400:
            row["errors"] += 1
    return sorted(stats.values(), key=lambda r: -r["requests"])[:top]
