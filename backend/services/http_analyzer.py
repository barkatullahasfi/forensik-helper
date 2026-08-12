"""
Ekstraksi transaksi HTTP lengkap: request, response, header, dan body.

Satu sumber data untuk log sesi maupun detektor OWASP. Keduanya membutuhkan
pasangan request/response yang sama; mengambilnya dua kali berarti dua pembacaan
penuh atas pcap untuk isi yang identik.

Header diambil apa adanya (`http.request.line`) supaya bisa dikutip verbatim di
laporan. Header yang diparafrase kehilangan nilainya sebagai bukti.
"""
from functools import lru_cache

from .. import config as settings
from .pcap_parser import run_tshark_fields

# Batas ukuran body yang disimpan. Body HTTP bisa berukuran megabyte; menyimpan
# utuh membuat berkas hasil analisis membengkak tanpa menambah nilai -- yang
# dibutuhkan analis adalah cuplikan yang cukup untuk mengenali isinya.
MAX_BODY_CHARS = 4000

# tshark menggabungkan field yang muncul berkali-kali (tiap baris header adalah
# satu kemunculan). Pemisahnya dipilih '|' karena koma lazim muncul DI DALAM
# nilai header (Accept, Cache-Control), sedangkan '|' hampir tidak pernah.
HEADER_SEPARATOR = "|"


def _split_headers(raw: str) -> list[str]:
    r"""
    Pecah baris header dan buang penanda akhir baris.

    `-T fields` meng-escape CRLF menjadi TEKS LITERAL '\r\n' (backslash, huruf r,
    backslash, huruf n) -- bukan karakter kontrol. Membiarkannya membuat setiap
    baris header di laporan berakhiran sampah yang terlihat seperti kesalahan
    penyalinan.
    """
    lines = []
    for line in (raw or "").split(HEADER_SEPARATOR):
        line = line.strip()
        for marker in ("\\r\\n", "\\n", "\\r"):
            if line.endswith(marker):
                line = line[: -len(marker)].rstrip()
        if line and line not in ("\\r\\n", ""):
            lines.append(line)
    return lines


def _clip(text: str) -> str:
    text = text or ""
    return text[:MAX_BODY_CHARS] + ("…" if len(text) > MAX_BODY_CHARS else "")


@lru_cache(maxsize=2)
def _raw(pcap_path: str) -> tuple:
    requests = run_tshark_fields(
        pcap_path, "http.request",
        ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst",
         "http.request.method", "http.request.uri", "http.host", "http.user_agent",
         "http.request.line", "http.file_data", "http.content_type"],
        aggregator=HEADER_SEPARATOR)
    responses = run_tshark_fields(
        pcap_path, "http.response",
        ["frame.number", "frame.time_epoch", "tcp.stream", "http.response.code",
         "http.response.phrase", "http.response.line", "http.file_data",
         "http.content_type", "http.content_length", "http.server"],
        aggregator=HEADER_SEPARATOR)
    return tuple(map(tuple, (map(_freeze, requests), map(_freeze, responses))))


def _freeze(row: dict) -> tuple:
    return tuple(sorted(row.items()))


def _thaw(row: tuple) -> dict:
    return dict(row)


def transactions(pcap_path) -> list[dict]:
    """
    Pasangan request/response, dikorelasikan lewat tcp.stream.

    Satu koneksi keep-alive memuat banyak transaksi berurutan, jadi request
    ke-N dipasangkan dengan response ke-N pada stream yang sama. Response bisa
    None kalau koneksi terputus sebelum server menjawab -- itu informasi, bukan
    kekurangan data.
    """
    raw_requests, raw_responses = _raw(str(pcap_path))
    by_stream: dict[str, list[dict]] = {}
    for row in raw_responses:
        row = _thaw(row)
        by_stream.setdefault(row["tcp.stream"].split(HEADER_SEPARATOR)[0], []).append(row)

    counters: dict[str, int] = {}
    results = []
    for row in raw_requests:
        req = _thaw(row)
        stream = req["tcp.stream"].split(HEADER_SEPARATOR)[0]
        index = counters.get(stream, 0)
        counters[stream] = index + 1
        candidates = by_stream.get(stream, [])
        resp = candidates[index] if index < len(candidates) else None

        results.append({
            "tcp_stream": _int(stream),
            "frame_number": _int(req["frame.number"]),
            "timestamp": _float(req["frame.time_epoch"]),
            "src_ip": req["ip.src"].split(HEADER_SEPARATOR)[0],
            "dst_ip": req["ip.dst"].split(HEADER_SEPARATOR)[0],
            "request": {
                "method": req["http.request.method"].split(HEADER_SEPARATOR)[0],
                "uri": req["http.request.uri"].split(HEADER_SEPARATOR)[0],
                "host": req["http.host"].split(HEADER_SEPARATOR)[0],
                "user_agent": req["http.user_agent"].split(HEADER_SEPARATOR)[0],
                "headers": _split_headers(req["http.request.line"]),
                "content_type": req["http.content_type"].split(HEADER_SEPARATOR)[0],
                "body": _clip(req["http.file_data"]),
                "body_length": len(req["http.file_data"] or ""),
            },
            "response": {
                "status_code": _int(resp["http.response.code"].split(HEADER_SEPARATOR)[0]),
                "phrase": resp["http.response.phrase"].split(HEADER_SEPARATOR)[0],
                "server": resp["http.server"].split(HEADER_SEPARATOR)[0],
                "content_type": resp["http.content_type"].split(HEADER_SEPARATOR)[0],
                "content_length": _int(resp["http.content_length"].split(HEADER_SEPARATOR)[0]),
                "headers": _split_headers(resp["http.response.line"]),
                "body": _clip(resp["http.file_data"]),
                "body_length": len(resp["http.file_data"] or ""),
                "frame_number": _int(resp["frame.number"]),
            } if resp else None,
        })
    return results


def by_stream(pcap_path, limit_per_stream: int = 6) -> dict[int, list[dict]]:
    """Transaksi dikelompokkan per tcp.stream, untuk ditempelkan ke log sesi."""
    grouped: dict[int, list[dict]] = {}
    for item in transactions(pcap_path):
        stream = item["tcp_stream"]
        if stream is None:
            continue
        bucket = grouped.setdefault(stream, [])
        if len(bucket) < limit_per_stream:
            bucket.append(item)
    return grouped


def summarize(items: list[dict]) -> str:
    """
    Ringkasan satu baris untuk log sesi, kini menyertakan HASIL response.

    Daftar request tanpa response tidak menjawab pertanyaan yang sebenarnya
    diajukan: apakah permintaan itu berhasil?
    """
    parts = []
    for item in items:
        req, resp = item["request"], item["response"]
        target = f"{req['host']}{req['uri']}" if req["host"] else req["uri"]
        outcome = f" -> {resp['status_code']}" if resp and resp["status_code"] else " -> (tanpa response)"
        parts.append(f"{req['method']} {target}{outcome}")
    return " + ".join(parts)


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
