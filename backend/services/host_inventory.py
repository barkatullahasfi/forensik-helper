"""
Inventaris host di layer 2 dan layer 3, plus identifikasi vendor dari MAC.

Menjawab pertanyaan yang selalu muncul di awal analisis pcap: "sebenarnya ada
berapa host di sini, dan mesin macam apa mereka?"

Jumlah IP unik BUKAN jumlah host. Satu gateway meneruskan lalu lintas puluhan
alamat internet memakai satu MAC; menghitung IP membuat mereka tampak seperti
puluhan perangkat berbeda.
"""
import ipaddress
from collections import Counter

from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog

# OUI yang punya arti forensik, bukan salinan basis data IEEE.
#
# Yang penting di sini bukan merek kartu jaringannya, tapi jawaban atas satu
# pertanyaan: apakah mesin ini VIRTUAL? Bukti yang dianalisis sangat sering
# berasal dari lab atau sandbox, dan itu mengubah kesimpulan yang boleh ditulis
# di laporan -- "penyerang menembus perimeter organisasi" jadi klaim yang salah
# kalau ternyata dua VM di host yang sama.
OUI_VENDORS = {
    "08:00:27": ("Oracle VirtualBox", True),
    "0a:00:27": ("Oracle VirtualBox (host-only adapter)", True),
    "52:54:00": ("QEMU/KVM virtual NIC (juga dipakai gateway NAT VirtualBox)", True),
    "00:0c:29": ("VMware", True),
    "00:50:56": ("VMware (vSphere/Workstation)", True),
    "00:05:69": ("VMware ESX", True),
    "00:1c:14": ("VMware", True),
    "00:15:5d": ("Microsoft Hyper-V", True),
    "00:03:ff": ("Microsoft Virtual PC", True),
    "00:16:3e": ("Xen", True),
    "00:1c:42": ("Parallels", True),
    "02:42:ac": ("Docker container", True),
    "00:21:5d": ("Dell", False),
    "00:19:d1": ("Intel", False),
    "3c:5a:b4": ("Google", False),
    "b8:27:eb": ("Raspberry Pi Foundation", False),
    "dc:a6:32": ("Raspberry Pi Trading", False),
}

# Alamat khas VirtualBox mode NAT -- penguat independen dari OUI.
VIRTUALBOX_NAT_HINTS = {
    "10.0.2.15": "alamat guest default VirtualBox NAT",
    "10.0.2.2": "gateway default VirtualBox NAT",
    "10.0.2.3": "DNS server bawaan VirtualBox NAT",
}


def lookup_oui(mac: str) -> dict:
    """
    Vendor dari 3 oktet pertama, plus pemeriksaan bit U/L.

    Bit locally-administered (bit ke-2 dari oktet pertama) menandakan MAC
    di-set manual atau diacak -- fitur privasi di perangkat modern, tapi juga
    cara paling sederhana menyamarkan identitas perangkat.
    """
    mac = (mac or "").lower()
    if len(mac) < 8:
        return {"mac": mac, "vendor": None, "is_virtual": False, "locally_administered": False}
    prefix = mac[:8]
    vendor, virtual = OUI_VENDORS.get(prefix, (None, False))
    try:
        locally_administered = bool(int(mac[:2], 16) & 0b10)
    except ValueError:
        locally_administered = False
    return {
        "mac": mac, "oui": prefix, "vendor": vendor, "is_virtual": virtual,
        "locally_administered": locally_administered,
        "note": (f"Vendor tidak ada di tabel bawaan -- cek manual di basis data OUI IEEE "
                 f"untuk prefiks {prefix}" if not vendor else None),
    }


def _classify(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "privat"
    return "publik"


def build_inventory(pcap_path, evidence: EvidenceLog | None = None) -> dict:
    """
    Petakan MAC -> IP yang dipakainya, dan sebaliknya.

    Satu MAC dengan BANYAK IP publik hampir pasti router/gateway, bukan host.
    Membedakan ini penting: tanpa itu, laporan menyebut "14 host berkomunikasi"
    padahal secara fisik hanya ada tiga perangkat.
    """
    if evidence is None:
        evidence = EvidenceLog()
    rows = run_tshark_fields(pcap_path, "eth && ip", ["eth.src", "ip.src"])

    by_mac: dict[str, Counter] = {}
    for row in rows:
        mac = row["eth.src"].split(",")[0].lower()
        ip = row["ip.src"].split(",")[0]
        if mac and ip:
            by_mac.setdefault(mac, Counter())[ip] += 1

    devices = []
    for mac, ips in by_mac.items():
        info = lookup_oui(mac)
        public = [ip for ip in ips if _classify(ip) == "publik"]
        # Ambang 3: satu host bisa sah punya beberapa IP (multi-homing, alias),
        # tapi belasan IP publik di balik satu MAC hanya masuk akal untuk router.
        is_gateway = len(public) >= 3
        devices.append({
            **info,
            "ip_addresses": sorted(ips, key=lambda i: -ips[i]),
            "frame_count": sum(ips.values()),
            "role": "gateway/router" if is_gateway else "host",
            "public_ips_behind": len(public) if is_gateway else 0,
        })
    devices.sort(key=lambda d: -d["frame_count"])

    all_ips = {ip for ips in by_mac.values() for ip in ips}
    kinds = Counter(_classify(ip) for ip in all_ips)

    hosts = [d for d in devices if d["role"] == "host"]
    virtual = [d for d in hosts if d["is_virtual"]]
    for device in devices:
        evidence.track(
            "host_identified", f'eth.src == {device["mac"]}',
            f'{device["mac"]} -> {", ".join(device["ip_addresses"][:3])}',
            note=f'{device["role"]}, {device["frame_count"]} frame. '
                 + (f'Vendor: {device["vendor"]}. ' if device["vendor"] else
                    f'Vendor tidak dikenal (OUI {device.get("oui")}). ')
                 + ("MESIN VIRTUAL. " if device["is_virtual"] else "")
                 + ("MAC locally-administered (di-set manual atau diacak). "
                    if device["locally_administered"] else "")
                 + (f'{device["public_ips_behind"]} IP publik di baliknya -- ini perangkat '
                    "penerus, bukan host tersendiri" if device["role"] != "host" else ""))

    # Alamat khas NAT hanya berlaku kalau tidak dimiliki HOST tersendiri.
    # 10.0.2.3 memang DNS bawaan pada mode NAT biasa, tapi di mode NAT Network ia
    # bisa jadi VM ketiga dengan MAC guest-nya sendiri. Menyebutnya "DNS bawaan"
    # padahal daftar perangkat di ringkasan yang sama menampilkannya sebagai host
    # membuat laporan bertentangan dengan dirinya sendiri.
    host_owned = {ip for d in devices if d["role"] == "host" for ip in d["ip_addresses"]}
    nat_hints = {ip: hint for ip, hint in VIRTUALBOX_NAT_HINTS.items()
                 if ip in all_ips and ip not in host_owned}
    for ip in sorted(set(VIRTUALBOX_NAT_HINTS) & host_owned):
        nat_hints[ip] = (f"biasanya {VIRTUALBOX_NAT_HINTS[ip]}, TAPI di capture ini "
                         "alamat tersebut punya MAC guest sendiri -- jadi ia mesin "
                         "virtual tersendiri, bukan komponen NAT")
    if virtual or nat_hints:
        evidence.track(
            "virtual_environment", "eth.src (OUI) + alamat IP",
            f"{len(virtual)} dari {len(hosts)} host adalah mesin virtual",
            note="Bukti berasal dari lingkungan virtual/lab, bukan jaringan produksi. "
                 "Hindari kesimpulan tentang 'perimeter organisasi'. "
                 + (f"Penguat: {'; '.join(f'{ip} = {h}' for ip, h in nat_hints.items())}"
                    if nat_hints else ""))

    return {
        "devices": devices,
        "layer2_device_count": len(devices),
        "host_count": len(hosts),
        "gateway_count": len(devices) - len(hosts),
        "virtual_host_count": len(virtual),
        "ip_count_total": len(all_ips),
        "ip_breakdown": dict(kinds),
        "virtualbox_nat_indicators": nat_hints,
        "note": "Jumlah IP unik BUKAN jumlah host: alamat di balik satu gateway "
                "berbagi satu MAC. Sebutkan layer yang dihitung saat melaporkan.",
    }
