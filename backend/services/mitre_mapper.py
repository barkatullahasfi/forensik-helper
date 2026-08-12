"""
Mapping temuan ke MITRE ATT&CK — rule-based, bukan inferensi.

Tiap rule menyebut kondisi yang harus benar-benar ada di hasil analisis. Kalau
kondisinya tidak terpenuhi, technique-nya tidak muncul: laporan yang mendaftar
technique tanpa bukti pendukung lebih buruk daripada tidak menyebut apa pun.
"""

MITRE_RULES = [
    ("domain_rotation", "T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    ("suspected_beacon", "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("http_candidate_c2", "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("dga_domain", "T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    ("full_name", "T1087.002", "Account Discovery: Domain Account"),
    ("suspicious_file_download", "T1105", "Ingress Tool Transfer"),
    ("volume_spike", "T1041", "Exfiltration Over C2 Channel"),
    ("kerberos_rc4_downgrade", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    ("kerberos_long_tgt", "T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
    ("nonstandard_c2_port", "T1571", "Non-Standard Port"),
    ("port_protocol_mismatch", "T1071", "Application Layer Protocol"),
    ("known_malicious_ja3", "T1573", "Encrypted Channel"),
    ("threat_feed_match", "T1071", "Application Layer Protocol"),
    ("owasp_sqli", "T1190", "Exploit Public-Facing Application"),
    ("owasp_xss", "T1190", "Exploit Public-Facing Application"),
    ("owasp_command_injection", "T1190", "Exploit Public-Facing Application"),
    ("owasp_path_traversal", "T1083", "File and Directory Discovery"),
]


def map_findings_to_mitre(finding_types: list[str]) -> list[dict]:
    """
    Terima daftar finding_type yang benar-benar muncul (dari EvidenceLog),
    return technique unik beserta temuan mana yang mendukungnya.
    """
    present = set(finding_types)
    by_technique: dict[str, dict] = {}
    for condition, technique, name in MITRE_RULES:
        if condition not in present:
            continue
        entry = by_technique.setdefault(technique, {
            "technique": technique, "name": name, "supporting_findings": []})
        entry["supporting_findings"].append(condition)
    return sorted(by_technique.values(), key=lambda t: t["technique"])


def map_from_evidence(evidence_records: list[dict]) -> list[dict]:
    return map_findings_to_mitre([r["finding_type"] for r in evidence_records])
