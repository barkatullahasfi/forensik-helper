"""
Deteksi pola serangan web OWASP Top 10 dari HTTP request — cara kerja WAF:
signature/regex matching, bukan AI/ML.

Berguna untuk skenario "serangan TERHADAP web server", bukan cuma "korban
terinfeksi malware".

Aturan wajib modul ini: setiap temuan HARUS membawa response-nya. Laporan yang
cuma mendaftar payload mencurigakan tidak menjawab pertanyaan sebenarnya --
"serangannya berhasil atau tidak?"
"""
import re
from urllib.parse import unquote_plus

from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, to_utc

SQLI_PATTERNS = [
    r"(union)(\s|/\*.*?\*/|\+|%20)+(all\s+)?(select)",
    r"(select)(.*?)(from)(.*?)(information_schema|sysobjects|pg_catalog|mysql\.user)",
    r"(sleep\(\s*\d+\s*\))|(benchmark\(\s*\d+)|(waitfor\s+delay)|(pg_sleep\()",
    r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"['\"]\s*(or|and)\s+['\"][^'\"]*['\"]\s*=\s*['\"]",
    r"(;|\s)(drop|truncate)\s+(table|database)\s",
    r"extractvalue\(|updatexml\(|load_file\(|into\s+outfile",
]

XSS_PATTERNS = [
    r"<script[^>]*>", r"</script\s*>",
    r"javascript\s*:", r"on(load|error|click|mouseover|focus|animationstart)\s*=",
    r"<img[^>]+src\s*=\s*[\"']?\s*(javascript:|x[\"']?\s+onerror)",
    r"<(iframe|svg|body|object|embed)[^>]*\son\w+\s*=",
    r"(document\.cookie|document\.write|eval\(|alert\(|prompt\()",
]

CMD_INJECTION_PATTERNS = [
    r"[;|&`]\s*(cat|ls|dir|whoami|id|uname|wget|curl|nc|ncat|bash|sh|powershell|cmd)\s",
    r"\$\([^)]+\)", r"`[^`]+`",
    r"\|\s*(cat|ls|whoami|id|nc)\b",
    r"(;|\|\||&&)\s*(rm|del)\s+-",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\){2,}",
    r"(%2e%2e[/\\%])|(\.\.%2f)|(%252e%252e)",
    r"(/etc/(passwd|shadow|hosts))|(boot\.ini)|(win\.ini)|(/proc/self/environ)",
    r"(c:\\windows\\system32)",
]

SSRF_PATTERNS = [
    r"(https?|file|gopher|dict|ftp)://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|169\.254\.169\.254)",
    r"file:///",
    r"(url|uri|next|redirect|dest|target|feed)=(https?%3a%2f%2f|https?://)(127\.|localhost|10\.|192\.168\.)",
]

CREDENTIAL_IN_URL = [r"(password|passwd|pwd|token|api_key|apikey|secret|auth)=[^&\s]{4,}"]

OWASP_RULE_MAP = {
    "A01:2021 - Broken Access Control (Path Traversal)": (PATH_TRAVERSAL_PATTERNS, "owasp_path_traversal"),
    "A02:2021 - Cryptographic Failures (kredensial di URL)": (CREDENTIAL_IN_URL, "owasp_credential_in_url"),
    "A03:2021 - Injection (SQLi)": (SQLI_PATTERNS, "owasp_sqli"),
    "A03:2021 - Injection (XSS)": (XSS_PATTERNS, "owasp_xss"),
    "A03:2021 - Injection (Command)": (CMD_INJECTION_PATTERNS, "owasp_command_injection"),
    "A10:2021 - Server-Side Request Forgery": (SSRF_PATTERNS, "owasp_ssrf"),
}

LEAK_INDICATORS = ("root:x:0:0", "[boot loader]", "[fonts]", "mysqli_", "SQL syntax",
                   "ORA-0", "PostgreSQL query failed", "Microsoft OLE DB",
                   "Warning: mysql", "Fatal error:", "Traceback (most recent call last)")

WAF_HEADERS = ("x-waf", "cf-ray", "mod_security", "x-sucuri-id", "x-cdn", "incap_ses")


def extract_http_pairs(pcap_path) -> list[dict]:
    """
    Pasangan request/response, dikorelasikan lewat tcp.stream.

    Diambil dari `http_analyzer` yang juga menyuplai log sesi -- satu pembacaan
    pcap untuk dua keperluan. Response WAJIB ikut: tanpa itu modul ini cuma
    mendaftar payload dan tidak bisa menyimpulkan apa pun.
    """
    from .http_analyzer import transactions
    pairs = []
    for item in transactions(pcap_path):
        req, resp = item["request"], item["response"]
        pairs.append({
            "frame_number": item["frame_number"],
            "timestamp": item["timestamp"],
            "src_ip": item["src_ip"],
            "dst_ip": item["dst_ip"],
            "tcp_stream": item["tcp_stream"],
            "method": req["method"], "host": req["host"], "uri": req["uri"],
            "body": req["body"],
            "response": {
                "status_code": resp["status_code"], "server": resp["server"],
                "content_type": resp["content_type"], "body": resp["body"],
                "headers": resp["headers"],
            } if resp else None,
        })
    return pairs


def classify_outcome(category: str, decoded_request: str, resp: dict | None) -> str:
    """
    Apa yang TERJADI setelah request, bukan cuma apa yang dikirim.

    blocked / error / leaked / reflected / no_effect / no_response
    """
    if resp is None:
        return "no_response"
    status = resp.get("status_code")
    body = resp.get("body") or ""

    if status == 403 or (status == 406 and any(h in str(resp).lower() for h in WAF_HEADERS)):
        return "blocked"
    if status and 500 <= status < 600:
        return "error"
    if status == 200 and any(ind in body for ind in LEAK_INDICATORS):
        return "leaked"
    if "XSS" in category and status == 200 and _payload_echoed(decoded_request, body):
        # Wajib cek payload benar-benar ada di body. Mengembalikan "reflected"
        # untuk SEMUA response 200 akan menaikkan setiap match regex XSS jadi
        # confidence HIGH -- pabrik false positive.
        return "reflected"
    return "no_effect"


def _payload_echoed(decoded_request: str, body: str) -> bool:
    """
    Reflected XSS = potongan payload attacker muncul apa adanya di response.

    Minimal 8 karakter supaya tidak ke-trigger '<b>' yang kebetulan sama.
    """
    if not body:
        return False
    candidates = re.findall(r"<[^<>]{7,120}>?", decoded_request)
    return any(c in body for c in candidates)


def _score_confidence(outcome: str) -> str:
    """Terima outcome yang SUDAH dihitung -- jangan panggil classify_outcome dua kali."""
    return "HIGH" if outcome in ("leaked", "reflected", "error") else "MEDIUM"


def detect_owasp_patterns(pcap_path, evidence: EvidenceLog | None = None) -> list[dict]:
    if evidence is None:
        evidence = EvidenceLog()
    findings = []
    for pair in extract_http_pairs(pcap_path):
        # unquote_plus: query string dan body form meng-encode spasi sebagai '+'.
        # Dengan unquote biasa, "1'+OR+'1'='1" tidak cocok dengan satu pun pola
        # SQLi -- semuanya menuntut spasi. Ditemukan saat menguji log IIS, tapi
        # celahnya sama persis di jalur pcap ini.
        decoded = unquote_plus(f"{pair['uri']} {pair['body']}")
        for category, (patterns, finding_type) in OWASP_RULE_MAP.items():
            matched = next((p for p in patterns if re.search(p, decoded, re.IGNORECASE)), None)
            if not matched:
                continue
            outcome = classify_outcome(category, decoded, pair["response"])
            resp = pair["response"] or {}
            query = (f"http.request.uri contains \"{pair['uri'][:60]}\""
                     if pair["uri"] else f"tcp.stream=={pair['tcp_stream']}")
            findings.append({
                "timestamp": pair["timestamp"],
                "time_utc": to_utc(pair["timestamp"]),
                "frame_number": pair["frame_number"],
                "src_ip": pair["src_ip"], "dst_ip": pair["dst_ip"],
                "owasp_category": category,
                "matched_pattern": matched,
                "http_method": pair["method"],
                "host": pair["host"],
                "request_uri": pair["uri"],
                "request_snippet": decoded[:300],
                "response_status": resp.get("status_code"),
                "response_body_snippet": (resp.get("body") or "")[:500] or None,
                "outcome": outcome,
                "confidence": _score_confidence(outcome),
                "evidence_query": query,
            })
            evidence.track(finding_type, query,
                           f"{category} dari {pair['src_ip']} -> {pair['dst_ip']}",
                           note=f"Outcome: {outcome}. Response "
                                f"{resp.get('status_code') or '(tidak ada)'}. "
                                "Signature-based -- rawan false positive, "
                                "verifikasi isi request lengkapnya")
            # TIDAK break di sini. `next()` di atas sudah membatasi satu match
            # per kategori. Break akan menghentikan pemeriksaan kategori
            # BERIKUTNYA, sehingga payload yang sekaligus SQLi dan path traversal
            # (mis. LOAD_FILE('/etc/passwd')) hanya dilaporkan sebagai salah satu
            # -- yang mana, ditentukan urutan dict. Terlihat di WebInvestigation.pcap.
    return findings


def summarize(findings: list[dict]) -> dict:
    outcomes: dict[str, int] = {}
    categories: dict[str, int] = {}
    for f in findings:
        outcomes[f["outcome"]] = outcomes.get(f["outcome"], 0) + 1
        categories[f["owasp_category"]] = categories.get(f["owasp_category"], 0) + 1
    return {"total": len(findings), "by_outcome": outcomes, "by_category": categories,
            "attackers": sorted({f["src_ip"] for f in findings})}


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
