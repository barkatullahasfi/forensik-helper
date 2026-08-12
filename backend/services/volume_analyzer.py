"""
Deteksi lonjakan volume data keluar — kandidat exfiltration.

Threshold absolut (mis. "> 50 MB per menit") tidak berguna lintas pcap: capture
kantor 8 jam dan capture latihan 5 menit punya baseline yang jauh berbeda.
Modul ini memakai threshold absolut DAN relatif terhadap baseline capture itu
sendiri.
"""
import statistics

from .pcap_parser import run_tshark_fields
from .timeline_builder import EvidenceLog, to_utc


def detect_data_exfil_spikes(pcap_path, internal_ip: str, bucket_seconds: int = 60,
                             threshold_mb: float = 5.0, sigma: float = 3.0,
                             evidence: EvidenceLog | None = None) -> dict:
    """
    Bagi traffic outbound jadi bucket waktu, flag bucket yang jauh di atas
    baseline-nya sendiri (mean + sigma*stddev) ATAU melewati threshold absolut.
    """
    if evidence is None:
        evidence = EvidenceLog()
    rows = run_tshark_fields(pcap_path, f"ip.src=={internal_ip}",
                             ["frame.time_epoch", "frame.len", "ip.dst"])
    if not rows:
        return {"buckets": [], "spikes": [], "total_bytes_out": 0, "top_destinations": []}

    buckets: dict[int, int] = {}
    per_dest: dict[str, int] = {}
    for row in rows:
        ts, size = _float(row["frame.time_epoch"]), _int(row["frame.len"])
        if ts is None or size is None:
            continue
        buckets[int(ts // bucket_seconds)] = buckets.get(int(ts // bucket_seconds), 0) + size
        dst = row["ip.dst"].split(",")[0]
        per_dest[dst] = per_dest.get(dst, 0) + size

    volumes = list(buckets.values())
    mean = statistics.mean(volumes)
    stdev = statistics.stdev(volumes) if len(volumes) > 1 else 0.0
    relative_cut = mean + sigma * stdev
    absolute_cut = threshold_mb * 1024 * 1024

    series, spikes = [], []
    for index in sorted(buckets):
        total = buckets[index]
        start = index * bucket_seconds
        entry = {"bucket_start": start, "bucket_start_utc": to_utc(start),
                 "total_bytes": total, "total_mb": round(total / 1048576, 3)}
        series.append(entry)
        if total >= absolute_cut or (stdev > 0 and total >= relative_cut):
            reason = []
            if total >= absolute_cut:
                reason.append(f"melewati ambang absolut {threshold_mb} MB")
            if stdev > 0 and total >= relative_cut:
                reason.append(f"{(total - mean) / stdev:.1f}x stddev di atas rata-rata capture")
            spike = {**entry, "reason": " dan ".join(reason), "confidence": "MEDIUM"}
            spikes.append(spike)
            evidence.track(
                "volume_spike",
                f"ip.src=={internal_ip} && frame.time_epoch >= {start} && "
                f"frame.time_epoch < {start + bucket_seconds}",
                f"{entry['total_mb']} MB keluar dalam {bucket_seconds} detik",
                note=f"{spike['reason']}. Upload besar juga bisa aktivitas sah "
                     "(backup, sync cloud) -- cek destinasinya dulu")

    top = sorted(per_dest.items(), key=lambda kv: -kv[1])[:10]
    return {
        "bucket_seconds": bucket_seconds,
        "baseline_mean_bytes": round(mean, 1),
        "baseline_stdev_bytes": round(stdev, 1),
        "total_bytes_out": sum(volumes),
        "total_mb_out": round(sum(volumes) / 1048576, 2),
        "buckets": series,
        "spikes": spikes,
        "top_destinations": [{"ip": ip, "bytes": b, "mb": round(b / 1048576, 3)}
                             for ip, b in top],
    }


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
