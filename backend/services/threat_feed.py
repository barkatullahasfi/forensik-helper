"""
Cross-check reputasi domain/IP/hash/JA3 ke feed offline Abuse.ch.

Feed di-download berkala jadi CSV lokal lalu di-load ke set Python: lookup O(1),
tanpa API key, tanpa rate limit, dan tetap jalan offline.

Parsing feed adalah titik gagal paling SENYAP di seluruh tools: kalau kolomnya
salah, tidak ada exception -- semua lookup cuma mengembalikan False selamanya.
Karena itu tiap loader di sini punya komentar soal bentuk data aslinya.
"""
import csv
from pathlib import Path
from urllib.parse import urlparse

from .. import config as settings
from .timeline_builder import EvidenceLog, is_noise

# Layanan hosting/berbagi file publik: kemunculannya di URLhaus berarti ada URL
# jahat yang dititipkan di sana, bukan bahwa domainnya sendiri berbahaya.
SHARED_HOSTING_HINTS = ("drive.google", "dropbox", "onedrive", "1drv.ms", "mega.nz",
                        "mediafire", "discord", "github", "githubusercontent",
                        "pastebin", "archive.org", "bitbucket", "gitlab",
                        "amazonaws", "blob.core.windows.net", "firebasestorage",
                        "cdn.jsdelivr", "sourceforge", "wetransfer", "sendspace")

FEED_URLS = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    "sslbl_ja3": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
}


def download_feeds(storage_dir=None) -> dict[str, str]:
    """
    Dijalankan berkala (mis. tiap 6 jam), BUKAN tiap analisis -- supaya tidak
    membebani server Abuse.ch dan analisis tidak bergantung pada koneksi.
    """
    import httpx
    directory = Path(storage_dir or settings.FEED_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    status = {}
    for name, url in FEED_URLS.items():
        try:
            resp = httpx.get(url, timeout=60, follow_redirects=True)
            resp.raise_for_status()
            content = resp.content
            # URLhaus/ThreatFox membungkus CSV dalam ZIP di beberapa endpoint.
            if content[:2] == b"PK":
                import io
                import zipfile
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    content = zf.read(zf.namelist()[0])
            (directory / f"{name}.csv").write_bytes(content)
            status[name] = f"ok ({len(content)} byte)"
        except Exception as e:  # noqa: BLE001 -- satu feed gagal tidak boleh
            status[name] = f"gagal: {e}"      # menggagalkan yang lain
    return status


def _rows(feed_path):
    """
    Baris CSV non-komentar, quote sudah dibersihkan.

    Feed Abuse.ch punya preamble baris '#' dan kolom ber-quote dengan spasi
    setelah koma -- dua-duanya harus dibersihkan sebelum dipakai lookup.
    """
    path = Path(feed_path)
    if not path.exists():
        return
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if row and not row[0].lstrip().startswith("#"):
                yield [c.strip().strip('"') for c in row]


def load_urlhaus_hosts(feed_path) -> set[str]:
    """
    URLhaus kolom 2 berisi URL LENGKAP ('http://1.2.3.4/x.exe'), BUKAN domain.
    Wajib di-parse jadi hostname -- kalau di-set apa adanya, check_domain() tidak
    akan pernah match satu pun.
    """
    hosts = set()
    for row in _rows(feed_path):
        if len(row) > 2:
            host = urlparse(row[2]).hostname
            if host:
                hosts.add(host.lower())
    return hosts


def load_threatfox_iocs(feed_path) -> tuple[set[str], set[str]]:
    """
    ThreatFox: kolom 2 = ioc_value, kolom 3 = ioc_type.

    Untuk tipe 'ip:port' nilainya berformat '1.2.3.4:443' -- PORT HARUS DIBUANG,
    kalau tidak check_ip('1.2.3.4') gagal terus. Return (host/ip, hash).
    """
    hosts, hashes = set(), set()
    for row in _rows(feed_path):
        if len(row) < 4:
            continue
        value, ioc_type = row[2].lower(), row[3].lower()
        if "hash" in ioc_type:
            hashes.add(value)
        elif ioc_type.startswith("url"):
            host = urlparse(value).hostname
            if host:
                hosts.add(host)
        elif ioc_type.startswith("ip"):
            # ponytail: rsplit cukup untuk IPv4:port yang dipakai ThreatFox.
            # Ganti ke ipaddress.ip_address() kalau feed memuat IPv6 bracket.
            hosts.add(value.rsplit(":", 1)[0])
        else:
            hosts.add(value)
    return hosts, hashes


def load_ja3_set(feed_path) -> set[str]:
    """SSLBL ja3_fingerprints.csv -- kolom 0 = ja3_md5."""
    return {row[0].lower() for row in _rows(feed_path) if row and len(row[0]) == 32}


class ThreatFeedChecker:
    def __init__(self, storage_dir=None):
        d = Path(storage_dir or settings.FEED_DIR)
        self.malicious_hosts = load_urlhaus_hosts(d / "urlhaus.csv")
        tf_hosts, tf_hashes = load_threatfox_iocs(d / "threatfox.csv")
        self.malicious_hosts |= tf_hosts
        self.malicious_hashes = tf_hashes
        self.malicious_ja3 = load_ja3_set(d / "sslbl_ja3.csv")
        self.loaded = bool(self.malicious_hosts or self.malicious_hashes)

    def stats(self) -> dict:
        return {"hosts": len(self.malicious_hosts), "hashes": len(self.malicious_hashes),
                "ja3": len(self.malicious_ja3), "loaded": self.loaded}

    def check_domain(self, domain: str) -> dict:
        bad = domain.lower().rstrip(".") in self.malicious_hosts
        return {"value": domain, "type": "domain", "is_known_malicious": bad,
                "source": "abuse.ch" if bad else None}

    def check_ip(self, ip: str) -> dict:
        bad = ip in self.malicious_hosts
        return {"value": ip, "type": "ip", "is_known_malicious": bad,
                "source": "abuse.ch" if bad else None}

    def check_ja3(self, ja3_hash: str) -> dict:
        bad = ja3_hash.lower() in self.malicious_ja3
        return {"value": ja3_hash, "type": "ja3", "is_known_malicious": bad,
                "source": "SSLBL" if bad else None}

    def check_file_hash(self, file_hash: str) -> dict:
        bad = file_hash.lower() in self.malicious_hashes
        return {"value": file_hash, "type": "hash", "is_known_malicious": bad,
                "source": "ThreatFox" if bad else None}


def check_iocs(checker: ThreatFeedChecker, domains: list[str], ips: list[str],
               evidence: EvidenceLog | None = None) -> list[dict]:
    """Cek sekumpulan IOC, kembalikan yang cocok saja."""
    if evidence is None:
        evidence = EvidenceLog()
    hits = []
    for domain in set(filter(None, domains)):
        result = checker.check_domain(domain)
        if result["is_known_malicious"]:
            query = f'dns.qry.name == "{domain}" || http.host == "{domain}"'
            # URLhaus mendaftar URL SPESIFIK, dan kita hanya menyimpan hostname-nya.
            # Untuk layanan hosting/file-sharing publik, itu berarti "pernah ada
            # satu file jahat di sana", BUKAN "domain ini jahat". Melaporkan
            # drive.google.com sebagai IOC malware adalah kesalahan yang mahal
            # di laporan -- diturunkan jadi LOW dengan penjelasan.
            shared = is_noise([domain]) or any(
                h in domain for h in SHARED_HOSTING_HINTS)
            result = {**result, "confidence": "LOW" if shared else "HIGH",
                      "shared_hosting": shared, "evidence_query": query}
            hits.append(result)
            evidence.track(
                "threat_feed_match", query, domain,
                note="Terdaftar di feed abuse.ch (URLhaus/ThreatFox)" if not shared else
                     "Domain layanan hosting/berbagi file publik. URLhaus mendaftar "
                     "URL SPESIFIK di host ini, bukan host-nya sendiri -- JANGAN "
                     "laporkan domain ini sebagai IOC tanpa mencocokkan path URL-nya")
    for ip in set(filter(None, ips)):
        result = checker.check_ip(ip)
        if result["is_known_malicious"]:
            query = f"ip.addr == {ip}"
            hits.append({**result, "evidence_query": query})
            evidence.track("threat_feed_match", query, ip,
                           note="Terdaftar di feed abuse.ch (ThreatFox)")
    return hits
