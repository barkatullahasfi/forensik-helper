"""
Wrapper tshark. Semua modul analisis pcap bergantung pada modul ini.

Memakai `-T fields` (bukan `-T json`): outputnya TSV datar, tidak perlu flatten
struktur `_source.layers` yang tiap value-nya array.
"""
import ipaddress
import re
from collections import Counter
from functools import lru_cache

from .. import config as settings
from . import tools
from .tools import run

# tshark memakai '/t' sebagai literal tab di opsi -E separator.


def run_tshark_fields(pcap_path, display_filter: str, fields: list[str],
                      timeout: int | None = None, aggregator: str = ",") -> list[dict]:
    """
    Jalankan tshark dengan display filter dan field tertentu.
    Return satu dict per paket; paket yang semua field-nya kosong dibuang.

    `aggregator` menentukan pemisah untuk field yang muncul berkali-kali dalam
    satu paket (mis. tiap baris header HTTP). Default koma cocok untuk field
    sederhana, tapi untuk header HTTP koma lazim muncul DI DALAM nilainya --
    pemanggil yang mengambil header sebaiknya memilih pemisah lain.
    """
    opts = ["-E", "separator=/t", "-E", "occurrence=a", "-E", f"aggregator={aggregator}"]
    cmd = [tools.resolve("tshark"), "-r", str(pcap_path), "-T", "fields", *opts]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    out = run(cmd, timeout=timeout or settings.TSHARK_TIMEOUT)
    rows = []
    for line in out.splitlines():
        values = line.split("\t")
        # Baris pendek terjadi kalau field terakhir kosong; padding supaya zip aman.
        values += [""] * (len(fields) - len(values))
        row = dict(zip(fields, values))
        if any(row.values()):
            rows.append(row)
    return rows


def run_tshark_verbose(pcap_path, display_filter: str) -> str:
    """
    `tshark -V` -- untuk field yang tidak punya nama field pendek yang bisa
    dipakai `-e` (kasus SAMR Full Name). Return stdout mentah untuk di-regex.
    """
    return run([tools.resolve("tshark"), "-r", str(pcap_path), "-Y", display_filter, "-V"],
               timeout=settings.TSHARK_TIMEOUT)


def get_capture_info(pcap_path) -> dict:
    """
    First/last packet time (UTC), jumlah paket, durasi.

    Pakai `capinfos` (ikut terinstall bersama tshark di semua platform) daripada
    membaca ulang seluruh pcap lewat tshark -- capinfos hanya baca header.

    `-S` WAJIB: tanpa itu capinfos mencetak waktu dalam ZONA LOKAL mesin yang
    menjalankan analisis. Laporan forensik yang mencampur waktu lokal analis
    dengan waktu UTC event adalah kesalahan yang sulit dilacak belakangan.
    Dengan -S nilainya epoch, lalu diformat sendiri ke UTC.
    """
    out = run([tools.resolve("capinfos"), "-a", "-e", "-c", "-u", "-M", "-S",
               str(pcap_path)], timeout=settings.TSHARK_TIMEOUT)
    info = {}
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            info[key.strip()] = value.strip()

    def pick(*names):
        return next((info[n] for n in names if n in info), None)

    # Nama field berbeda antar versi Wireshark.
    first = _float(pick("Earliest packet time", "First packet time", "Start time"))
    last = _float(pick("Latest packet time", "Last packet time", "End time"))
    return {
        "file": str(pcap_path),
        "packet_count": _int(pick("Number of packets")),
        "first_packet_epoch": first,
        "last_packet_epoch": last,
        "first_packet": _to_utc(first),
        "last_packet": _to_utc(last),
        "duration_sec": _float(pick("Capture duration")),
    }


def _to_utc(epoch):
    if epoch is None:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _int(value):
    try:
        return int(str(value).split()[0].replace(",", "").replace(".", ""))
    except (ValueError, AttributeError, IndexError):
        return None


def _float(value):
    """
    Parse angka dari output capinfos.

    capinfos memformat desimal MENGIKUTI LOCALE sistem: di mesin dengan locale
    Indonesia/Jerman/Prancis nilainya '623,925423', bukan '623.925423'. Tanpa
    penanganan ini float() gagal dan seluruh informasi waktu capture diam-diam
    jadi None -- termasuk di narasi laporan.
    """
    if value is None:
        return None
    token = str(value).split()[0] if str(value).split() else ""
    if not token:
        return None
    # Koma sebagai pemisah desimal hanya kalau tidak ada titik sama sekali.
    if "," in token and "." not in token:
        token = token.replace(",", ".")
    else:
        token = token.replace(",", "")
    try:
        return float(token)
    except ValueError:
        return None


def protocol_summary(pcap_path) -> dict[str, int]:
    """
    Protokol apa saja yang ADA di pcap, beserta jumlah frame-nya.

    Satu pass `tshark -z io,phs` (~3 detik untuk 28 MB) menghemat belasan pass
    lain: tanpa ini pipeline tetap menjalankan analisis Kerberos, JA3/TLS,
    NBNS/DHCP, dan carving SMB/FTP/TFTP pada capture yang sama sekali tidak
    memuat protokol-protokol itu. Pada capture web 88.862 paket, 12 dari ~30
    pass yang dijalankan tidak mungkin menghasilkan apa pun.
    """
    out = run([tools.resolve("tshark"), "-q", "-z", "io,phs", "-r", str(pcap_path)],
              timeout=settings.TSHARK_TIMEOUT, check=False)
    found: dict[str, int] = {}
    for line in out.splitlines():
        match = re.match(r"^\s+(\S+)\s+frames:(\d+)", line)
        if match:
            found[match.group(1)] = found.get(match.group(1), 0) + int(match.group(2))
    return found


def has_protocol(protocols: dict[str, int] | None, *names: str) -> bool:
    """None = probe tidak dijalankan; jangan melewatkan modul apa pun karena ragu."""
    if protocols is None:
        return True
    return any(protocols.get(n) for n in names)


@lru_cache(maxsize=4)
def _traffic_matrix(pcap_path: str) -> tuple:
    """
    Satu pass tshark -> hitungan paket, byte, dan waktu per pasangan host.

    TIDAK memakai `tshark -z conv,ip`: tabel itu diformat untuk mata manusia --
    satuannya berubah-ubah ("184 kB", "1032 bytes") dan angkanya mengikuti locale
    ("78,082576000"), jadi parsing posisionalnya rapuh persis seperti bug capinfos
    sebelumnya. Menghitung sendiri dari field mentah menghasilkan byte eksak,
    dan pass ini juga dipakai rank_hosts sehingga tidak ada pembacaan tambahan.
    """
    rows = run_tshark_fields(pcap_path, "ip",
                             ["ip.src", "ip.dst", "frame.len", "frame.time_epoch"])
    directed: dict[tuple, dict] = {}
    for row in rows:
        src = row["ip.src"].split(",")[0]
        dst = row["ip.dst"].split(",")[0]
        size = _int(row["frame.len"]) or 0
        when = _float(row["frame.time_epoch"])
        entry = directed.setdefault((src, dst), {"frames": 0, "bytes": 0,
                                                 "first": when, "last": when})
        entry["frames"] += 1
        entry["bytes"] += size
        if when is not None:
            entry["first"] = min(entry["first"] or when, when)
            entry["last"] = max(entry["last"] or when, when)
    return tuple(sorted((src, dst, v["frames"], v["bytes"], v["first"], v["last"])
                        for (src, dst), v in directed.items()))


def conversations(pcap_path) -> list[dict]:
    """
    Byte yang mengalir ke MASING-MASING arah per pasangan host.

    Dipakai menjawab "data apa yang mereka ambil". Menghitung paket saja tidak
    cukup: 4000 paket SYN pemindaian membawa jauh lebih sedikit data daripada 20
    response HTTP. Yang menunjukkan perpindahan data adalah byte, beserta arahnya.
    """
    pairs: dict[tuple, dict] = {}
    for src, dst, frames, size, first, last in _traffic_matrix(str(pcap_path)):
        key = tuple(sorted((src, dst)))
        entry = pairs.setdefault(key, {
            "host_a": key[0], "host_b": key[1], "a_to_b_frames": 0, "a_to_b_bytes": 0,
            "b_to_a_frames": 0, "b_to_a_bytes": 0, "first_seen": first, "last_seen": last})
        prefix = "a_to_b" if src == key[0] else "b_to_a"
        entry[f"{prefix}_frames"] += frames
        entry[f"{prefix}_bytes"] += size
        if first is not None:
            entry["first_seen"] = min(entry["first_seen"] or first, first)
            entry["last_seen"] = max(entry["last_seen"] or last, last)

    for entry in pairs.values():
        entry["total_bytes"] = entry["a_to_b_bytes"] + entry["b_to_a_bytes"]
    return sorted(pairs.values(), key=lambda r: -r["total_bytes"])


def bytes_between(convs: list[dict], host: str, peer: str) -> dict | None:
    """Byte antara dua host, dinormalisasi ke sudut pandang `host`."""
    for row in convs:
        if {row["host_a"], row["host_b"]} == {host, peer}:
            if row["host_a"] == host:
                return {"sent": row["a_to_b_bytes"], "received": row["b_to_a_bytes"],
                        "frames_sent": row["a_to_b_frames"],
                        "frames_received": row["b_to_a_frames"]}
            return {"sent": row["b_to_a_bytes"], "received": row["a_to_b_bytes"],
                    "frames_sent": row["b_to_a_frames"],
                    "frames_received": row["a_to_b_frames"]}
    return None


def rank_hosts(pcap_path) -> list[dict]:
    """
    Peringkat host berdasarkan TOTAL paket (kirim + terima).

    Memakai ip.src saja SALAH untuk capture serangan: yang paling banyak
    mengirim justru penyerang, bukan korban. Pada capture uji, 10.0.2.4
    mengirim 4166 paket (penyerang) sementara 10.0.2.15 menerima 4248 (korban,
    dan itulah host asal RAM dump). Menghitung kedua arah memilih korban.

    Host privat DIDAHULUKAN, tapi tidak diwajibkan: capture yang diambil DI SISI
    SERVER tidak punya satu pun alamat privat -- semuanya publik. Menolak pcap
    seperti itu berarti tools ini menampik justru skenario yang modul OWASP-nya
    sendiri dibuat untuk menanganinya.
    """
    rows = run_tshark_fields(pcap_path, "ip", ["ip.src", "ip.dst"])
    sent, received = Counter(), Counter()
    for row in rows:
        sent[row["ip.src"].split(",")[0]] += 1
        received[row["ip.dst"].split(",")[0]] += 1

    hosts = []
    for ip in set(sent) | set(received):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_multicast or addr.is_unspecified:
            continue
        hosts.append({"ip": ip, "is_private": addr.is_private,
                      "packets_sent": sent[ip], "packets_received": received[ip],
                      "packets_total": sent[ip] + received[ip]})

    # SEMUA host dikembalikan (dibutuhkan korelasi lintas evidence sebagai
    # `all_ips`); prioritas privat diterapkan pada URUTAN, bukan dengan membuang.
    # Membuang IP publik di sini berarti pemanggil harus membaca pcap sekali lagi
    # hanya untuk mendapatkan daftar IP yang lengkap.
    any_private = any(h["is_private"] for h in hosts)
    scope = "privat" if any_private else "semua host (tidak ada IP privat)"
    for host in hosts:
        host["ranking_scope"] = scope
    return sorted(hosts, key=lambda h: (not h["is_private"] if any_private else False,
                                        -h["packets_total"]))


# Nama lama; sebagian pemanggil masih memakainya.
rank_internal_hosts = rank_hosts


def guess_target_ip(pcap_path) -> str | None:
    """Host dengan lalu lintas total terbanyak. Tebakan, bukan fakta."""
    hosts = rank_hosts(pcap_path)
    return hosts[0]["ip"] if hosts else None


def all_ips(pcap_path) -> set[str]:
    """
    SEMUA IP yang muncul di capture, ke arah mana pun.

    Dibutuhkan korelasi lintas evidence: `all_sessions` hanya memuat lalu lintas
    keluar dari satu host target, jadi mencocokkan koneksi RAM dump terhadapnya
    akan gagal setiap kali dump berasal dari host yang BUKAN target itu.
    """
    rows = run_tshark_fields(pcap_path, "ip", ["ip.src", "ip.dst"])
    found = set()
    for row in rows:
        found.add(row["ip.src"].split(",")[0])
        found.add(row["ip.dst"].split(",")[0])
    return {ip for ip in found if ip}


def build_dns_map(pcap_path) -> dict[str, list[str]]:
    """
    Peta IP -> nama domain yang me-resolve ke IP itu, dari jawaban DNS di pcap.

    Tanpa ini, hasil beacon detection cuma daftar IP mentah -- praktis tidak
    bisa ditempel ke laporan tanpa lookup manual satu per satu.
    """
    rows = run_tshark_fields(pcap_path, "dns.flags.response==1",
                             ["dns.qry.name", "dns.a", "dns.cname"])
    mapping: dict[str, list[str]] = {}
    for row in rows:
        names = [n for n in row["dns.qry.name"].split(",") if n]
        # Query SRV ('_ldap._tcp.<...>') membawa A record di additional section
        # untuk host yang BERBEDA dari nama query-nya. Memetakannya membuat IP
        # domain controller muncul di laporan dengan label '_ldap._tcp...'.
        names = [n for n in names if not n.startswith("_")]
        if not names:
            continue
        for ip in row["dns.a"].split(","):
            if ip:
                for name in names:
                    mapping.setdefault(ip, [])
                    if name not in mapping[ip]:
                        mapping[ip].append(name)
    return mapping


def tshark_version() -> str:
    out = run([tools.resolve("tshark"), "--version"], timeout=60)
    match = re.search(r"(\d+\.\d+\.\d+)", out)
    return match.group(1) if match else out.splitlines()[0]
