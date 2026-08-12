"""
Ekstraksi identitas host: IP, MAC, hostname, username AD, full name.

Replikasi metodologi manual yang sudah divalidasi -- tiap fungsi mencatat filter
tshark persis yang dipakainya ke evidence log, supaya Appendix Reproducibility di
laporan tidak perlu disusun ulang dari ingatan.
"""
import re
from collections import Counter

from .pcap_parser import run_tshark_fields, run_tshark_verbose
from .timeline_builder import EvidenceLog


def extract_identity(pcap_path, target_ip: str, evidence: EvidenceLog | None = None,
                     protocols: dict[str, int] | None = None) -> dict:
    # `evidence or EvidenceLog()` SALAH: EvidenceLog punya __len__, jadi log yang
    # masih kosong bernilai falsy dan diam-diam diganti objek baru -- semua
    # temuan identitas hilang dari Appendix Reproducibility tanpa error apa pun.
    if evidence is None:
        evidence = EvidenceLog()
    # Tiap sumber identitas adalah satu pass penuh atas pcap. Melewati yang
    # protokolnya memang tidak ada menghemat sampai 5 pembacaan utuh.
    from .pcap_parser import has_protocol
    kerberos = has_protocol(protocols, "kerberos")
    return {
        "ip": target_ip,
        "mac": _get_mac_by_ip(pcap_path, target_ip, evidence),
        "hostname": _get_hostnames(pcap_path, target_ip, evidence, protocols),
        "username": (_get_username_via_kerberos(pcap_path, target_ip, evidence)
                     if kerberos else None),
        "full_name": (_get_fullname_via_samr(pcap_path, evidence)
                      if has_protocol(protocols, "samr", "dcerpc") else None),
    }


def _get_mac_by_ip(pcap_path, ip: str, evidence: EvidenceLog) -> str | None:
    """
    MAC dipilih berdasarkan frame count TERBANYAK, bukan yang muncul pertama.

    Satu IP bisa punya lebih dari satu eth.src dalam pcap (gateway yang
    mem-forward, ARP spoof, atau sekadar noise). Mengambil hasil pertama berarti
    hasilnya bergantung pada paket mana yang kebetulan lebih dulu.
    """
    display_filter = f"ip.src=={ip}"
    rows = run_tshark_fields(pcap_path, display_filter, ["eth.src"])
    counts = Counter(r["eth.src"] for r in rows if r["eth.src"])
    if not counts:
        return None
    mac, hits = counts.most_common(1)[0]
    evidence.track(
        "mac_address", f"{display_filter} && eth.src", mac,
        note=f"{hits}/{sum(counts.values())} frame. "
             + (f"Ada {len(counts)} MAC berbeda untuk IP ini, dipilih yang mayoritas: "
                f"{dict(counts)}" if len(counts) > 1 else "MAC tunggal, tidak ambigu"))
    return mac


def _get_hostnames(pcap_path, ip: str, evidence: EvidenceLog,
                   protocols: dict[str, int] | None = None) -> list[str]:
    """
    Hostname dikumpulkan dari tiga sumber independen: NBNS, DHCP, dan nama
    computer account Kerberos (yang berakhiran '$'). Ketiganya ditampilkan,
    tidak dipilih salah satu -- kalau berbeda, itu sendiri sebuah temuan.
    """
    from .pcap_parser import has_protocol
    found: dict[str, str] = {}  # hostname -> sumber

    for label, display_filter, field, needs in (
        ("NBNS", f"nbns && ip.src=={ip}", "nbns.name", ("nbns",)),
        ("DHCP", f"dhcp && ip.src=={ip}", "dhcp.option.hostname", ("dhcp", "bootp")),
        ("Kerberos (computer account)", f"kerberos.CNameString && ip.src=={ip}",
         "kerberos.CNameString", ("kerberos",)),
    ):
        if not has_protocol(protocols, *needs):
            continue
        try:
            rows = run_tshark_fields(pcap_path, display_filter, [field])
        except RuntimeError:
            # Field DHCP bernama 'bootp.option.hostname' di tshark lama; kalau
            # filternya tidak dikenal, lewati sumber ini daripada menggagalkan
            # seluruh ekstraksi identitas.
            continue
        for row in rows:
            for raw in row[field].split(","):
                name = _clean_hostname(raw)
                if not name:
                    continue
                if field == "kerberos.CNameString" and not raw.endswith("$"):
                    continue  # itu username manusia, bukan hostname
                found.setdefault(name, label)

    for name, source in found.items():
        evidence.track("hostname", f"ip.src=={ip} (sumber: {source})", name)
    return sorted(found)


def _clean_hostname(raw: str) -> str:
    """
    Buang suffix NetBIOS dan tanda computer account.

    tshark menuliskan nbns.name lengkap dengan penjelasan servicenya --
    'DESKTOP-ES9F3ML<00> (Workstation/Redirector)' -- jadi yang dipotong bukan
    cuma '<00>' di ujung, tapi '<XX>' beserta SEMUA yang mengikutinya. Tanpa itu
    satu host muncul 3x sebagai hostname berbeda di laporan.
    """
    name = re.sub(r"<[0-9a-fA-F]{2}>.*$", "", raw.strip()).strip()
    name = name.rstrip("$").strip()
    # '*' adalah nama wildcard NBNS (dipakai node status query), bukan hostname.
    # Tanpa filter ini ia muncul di laporan sebagai nama host.
    return "" if name in ("*", "__MSBROWSE__", "..__MSBROWSE__.") else name


def _get_username_via_kerberos(pcap_path, ip: str, evidence: EvidenceLog) -> str | None:
    """
    Username AD dari Kerberos CNameString.

    CNameString yang berakhiran '$' adalah COMPUTER account (mis.
    'DESKTOP-ES9F3ML$'), bukan user -- wajib di-exclude, kalau tidak hostname
    mesin akan dilaporkan sebagai nama user.
    """
    display_filter = f"kerberos.CNameString && ip.src=={ip}"
    rows = run_tshark_fields(pcap_path, display_filter, ["kerberos.CNameString"])
    names = Counter()
    for row in rows:
        for raw in row["kerberos.CNameString"].split(","):
            value = raw.strip()
            if value and not value.endswith("$"):
                names[value] += 1
    if not names:
        return None
    username, hits = names.most_common(1)[0]
    evidence.track(
        "username", display_filter, username,
        note=f"{hits} kemunculan. Hasil berakhiran '$' (computer account) di-exclude"
             + (f". Kandidat lain: {[n for n in names if n != username]}"
                if len(names) > 1 else ""))
    return username


def _get_fullname_via_samr(pcap_path, evidence: EvidenceLog) -> str | None:
    """
    Full Name dari respons SAMR QueryUserInfo (opnum 36).

    Field ini tidak punya nama field pendek yang bisa dipakai `-e`, jadi satu-
    satunya cara yang reliable adalah `tshark -V` lalu regex barisnya. Wajar
    kalau hasilnya None: banyak environment memang tidak pernah query info user.
    """
    display_filter = "samr.opnum==36"
    try:
        verbose = run_tshark_verbose(pcap_path, display_filter)
    except RuntimeError:
        return None
    # Dibaca baris per baris, BUKAN regex multiline atas seluruh blob.
    # `^\s*Full Name:\s*(.+?)$` terlihat benar tapi salah: `\s` juga cocok dengan
    # newline, jadi pada struktur SAMR yang bertingkat --
    #     Full Name:
    #         Name Len: 26
    #         Full Name: Gabriel Wyatt
    # -- baris header 'Full Name:' yang kosong akan melompati newline dan
    # menangkap 'Name Len: 26' sebagai nilainya.
    matches = []
    for line in verbose.splitlines():
        label, sep, value = line.strip().partition(":")
        if sep and label.strip() == "Full Name":
            value = value.strip()
            if value and value.lower() != "null":
                matches.append(value)
    if not matches:
        return None
    full_name = Counter(matches).most_common(1)[0][0]
    evidence.track(
        "full_name", display_filter, full_name,
        note="Field SAMR 'Full Name' tidak punya nama field pendek untuk -e; "
             "diambil dari output `tshark -V`, baris 'Full Name:' yang bernilai "
             "(bukan baris header struct dengan nama sama)")
    return full_name
