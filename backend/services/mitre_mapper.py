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
    ("remote_share_access", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("smb_tree_connect", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("smb_web_executable", "T1505.003", "Server Software Component: Web Shell"),
    ("attack_tool_identified", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    ("port_scan", "T1046", "Network Service Discovery"),
    ("exposed_service", "T1046", "Network Service Discovery"),
    ("persistence_mechanism", "T1547.001",
     "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
    ("memory_process_hollowing", "T1055.012", "Process Injection: Process Hollowing"),
    ("memory_code_injection", "T1055", "Process Injection"),
    ("binary_packer", "T1027.002", "Obfuscated Files or Information: Software Packing"),
    ("suspicious_outbound_connection", "T1571", "Non-Standard Port"),
]

# Eksekusi lewat utilitas Windows: sub-technique-nya ditentukan utilitas MANA
# yang dipakai, jadi tidak bisa dipetakan dari nama temuan saja. Nilai MITRE-nya
# sudah dihitung memory_analyzer dan dibawa di temuan itu sendiri.
LOLBIN_FINDING = "lolbin_execution"


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


def map_from_evidence(evidence_records: list[dict], extra: list[dict] | None = None) -> list[dict]:
    """
    `extra` memuat temuan yang sudah membawa ID MITRE sendiri (mis. eksekusi
    LOLBin, yang sub-technique-nya bergantung pada utilitas mana yang dipakai
    dan tidak bisa disimpulkan dari nama temuan).
    """
    mapped = map_findings_to_mitre([r["finding_type"] for r in evidence_records])
    known = {m["technique"] for m in mapped}
    for item in extra or []:
        technique = item.get("mitre_technique")
        if technique and technique not in known:
            known.add(technique)
            mapped.append({"technique": technique,
                           "name": item.get("mitre_name") or "",
                           "supporting_findings": [
                               f"{item.get('process')} -> "
                               f"{', '.join(item.get('targets') or item.get('unc_paths') or [])}"]})
    return sorted(mapped, key=lambda t: t["technique"])
