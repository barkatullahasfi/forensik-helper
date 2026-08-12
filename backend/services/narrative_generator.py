"""
Paragraf narasi bahasa Indonesia formal, siap tempel ke laporan insiden.

String templating murni — TIDAK ada LLM/AI generatif di sini. Semua kalimat
ditulis manual sebagai template dengan slot data, mirip mail-merge. Itu yang
membuat outputnya konsisten dan bisa dipertanggungjawabkan.
"""
from .timeline_builder import to_utc


def generate_narrative(result: dict) -> str:
    paragraphs = [
        _identity_paragraph(result),
        _activity_paragraph(result),
        _findings_paragraph(result),
        _limitation_paragraph(result),
    ]
    return "\n\n".join(p for p in paragraphs if p)


def _identity_paragraph(result: dict) -> str:
    identity = result.get("identity", {})
    info = result.get("capture_info", {})
    hostnames = identity.get("hostname") or []
    who = []
    if identity.get("username"):
        who.append(f"akun {identity['username']}")
    if identity.get("full_name"):
        who.append(f"atas nama {identity['full_name']}")

    sentence = (
        f"Analisis dilakukan terhadap berkas tangkapan lalu lintas jaringan "
        f"{info.get('file', 'capture')} yang memuat {info.get('packet_count', 'sejumlah')} paket "
        f"dengan rentang waktu {info.get('first_packet', '-')} hingga "
        f"{info.get('last_packet', '-')}.")

    host = f" Host yang menjadi fokus analisis beralamat IP {identity.get('ip')}"
    if identity.get("mac"):
        host += f" dengan alamat MAC {identity['mac']}"
    if hostnames:
        host += f", teridentifikasi sebagai {' / '.join(hostnames)}"
    if who:
        host += f", dan digunakan oleh {' '.join(who)}"
    return sentence + host + "."


def _activity_paragraph(result: dict) -> str:
    summary = result.get("session_summary", {})
    if not summary:
        return ""
    outbound = summary.get("sessions_outbound", 0)
    inbound = summary.get("sessions_inbound", 0)
    # Kalimat dibedakan menurut arah yang dominan: menuliskan "membuka N sesi
    # keluar" untuk capture di sisi server -- yang justru MENERIMA koneksi --
    # membuat laporan salah menggambarkan peran host yang diperiksa.
    if inbound > outbound:
        pembuka = (f"Selama periode tangkapan, host tersebut menerima {inbound} sesi TCP "
                   f"masuk dari {summary.get('unique_destinations', 0)} host berbeda"
                   + (f", dan membuka {outbound} sesi keluar" if outbound else ""))
    else:
        pembuka = (f"Selama periode tangkapan, host tersebut membuka {outbound} sesi TCP "
                   f"keluar menuju {summary.get('unique_destinations', 0)} tujuan berbeda"
                   + (f", serta menerima {inbound} sesi masuk" if inbound else ""))
    text = (
        f"{pembuka}. Dari keseluruhan sesi tersebut, "
        f"{summary.get('sessions_with_payload', 0)} memuat permintaan HTTP yang isinya "
        f"dapat dibaca, sedangkan {summary.get('sessions_idle', 0)} sesi lainnya hanya "
        f"berupa handshake tanpa muatan data.")

    rotation = result.get("domain_rotation") or []
    if rotation:
        top = max(rotation, key=lambda r: r["destination_count"])
        span = int(top["window_end"] - top["window_start"])
        text += (f" Teramati pula pola perpindahan tujuan yang padat, yakni "
                 f"{top['destination_count']} tujuan berbeda dalam rentang {span} detik "
                 f"terhitung sejak {top['window_start_utc']}.")
    return text


def _findings_paragraph(result: dict) -> str:
    candidates = [e for e in result.get("key_events", [])
                  if e.get("category") == "http_candidate_c2"]
    beacons = [b for b in result.get("beacons", [])
               if b.get("is_suspected_beacon") and not b.get("is_known_noise")]
    # Hit di layanan hosting publik TIDAK boleh masuk narasi sebagai IOC.
    # "Indikator drive.google.com tercatat sebagai malware" adalah kalimat yang
    # salah secara substansi: URLhaus mendaftar URL spesifik di host itu, bukan
    # host-nya. Tetap ada di data mentah dan appendix, cuma tidak dinarasikan.
    threat_hits = [h for h in (result.get("threat_feed_hits") or [])
                   if not h.get("shared_hosting")]
    files = [f for f in (result.get("carved_files") or []) if f.get("confidence") != "LOW"]

    if not (candidates or beacons or threat_hits or files):
        return ("Tidak ditemukan indikator komunikasi command-and-control yang menonjol "
                "pada berkas ini berdasarkan kriteria yang diterapkan. Perlu dicatat bahwa "
                "ketiadaan temuan bukan berarti host bersih, melainkan bahwa pola yang "
                "diperiksa tidak muncul dalam rentang waktu tangkapan ini.")

    parts = []
    for event in candidates[:3]:
        parts.append(
            f"Host melakukan komunikasi HTTP tidak terenkripsi ke {event['destination']} "
            f"dimulai pukul {event['time_utc']}. Karena muatannya terbaca, isi permintaan "
            f"dapat diperiksa langsung melalui filter {event['evidence_query']}")
    for beacon in beacons[:3]:
        parts.append(
            f"Terdapat pola koneksi berkala ke {beacon['label']} sebanyak "
            f"{beacon['connection_count']} kali dengan selang rata-rata "
            f"{beacon['mean_interval_sec']} detik (koefisien variasi "
            f"{beacon['coefficient_variation']}), yang menunjukkan keteraturan di luar "
            f"kelaziman aktivitas pengguna")
    for hit in threat_hits[:3]:
        parts.append(
            f"Indikator {hit['value']} tercatat dalam basis data ancaman publik "
            f"{hit['source']}")
    for file in files[:3]:
        parts.append(
            f"Berhasil diekstraksi berkas {file['filename']} ({file['file_size']} byte, "
            f"SHA256 {file['exact_hashes']['sha256']}) dari lalu lintas {file['protocol']}")
    return ". ".join(parts) + "."


def _limitation_paragraph(result: dict) -> str:
    lines = ["Sebagai catatan metodologis, seluruh temuan di atas diperoleh melalui "
             "analisis deterministik berbasis aturan dan statistik terhadap metadata "
             "serta muatan lalu lintas yang tidak terenkripsi."]
    if any(e.get("confidence") == "MEDIUM" for e in result.get("key_events", [])):
        lines.append("Temuan berlabel MEDIUM merupakan hasil inferensi dari pola dan "
                     "metadata, bukan pengamatan langsung atas isi muatan, sehingga "
                     "memerlukan verifikasi manual sebelum dijadikan kesimpulan.")
    lines.append("Lalu lintas terenkripsi TLS tidak dapat diperiksa isinya tanpa kunci "
                 "dekripsi, sehingga kemungkinan aktivitas lain di kanal tersebut tidak "
                 "dapat dikesampingkan.")
    lines.append("Seluruh filter yang digunakan untuk memperoleh tiap temuan "
                 "didokumentasikan pada Lampiran Reproduksibilitas.")
    return " ".join(lines)


def build_appendix(result: dict) -> str:
    """Lampiran reproduksibilitas dalam bentuk teks siap tempel."""
    lines = ["LAMPIRAN — REPRODUKSIBILITAS",
             "Filter berikut dapat dijalankan langsung di Wireshark atau tshark "
             "untuk memverifikasi tiap temuan.", ""]
    for i, record in enumerate(result.get("evidence_index", []), 1):
        lines.append(f"{i}. {record['finding_type']} — {record['result']}")
        lines.append(f"   Filter : {record['wireshark_filter']}")
        if record.get("note"):
            lines.append(f"   Catatan: {record['note']}")
        lines.append("")
    return "\n".join(lines)
