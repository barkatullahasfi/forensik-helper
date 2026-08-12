"""
Deteksi pola Domain Generation Algorithm — entropy + bentuk nama domain.

Murni aritmetika atas string nama domain; tidak menyentuh pcap.
"""
import math
from collections import Counter

UNCOMMON_TLDS = (".xyz", ".top", ".cc", ".shop", ".lat", ".sbs", ".cyou",
                 ".info", ".club", ".su", ".ru", ".tk", ".ml", ".ga", ".cf",
                 ".buzz", ".work", ".live", ".icu", ".rest", ".monster")

VOWELS = set("aeiou")


def calculate_entropy(text: str) -> float:
    """Shannon entropy. Domain DGA biasanya acak = entropy tinggi."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def normalized_entropy(label: str) -> float:
    """
    Entropy MENTAH tidak bisa dipakai sebagai threshold absolut.

    Entropy maksimum sebuah string = log2(panjangnya). Domain 9 huruf seperti
    'taibeinan' maksimum hanya 3.17, jadi threshold '> 3.3' yang sering dipakai
    TIDAK PERNAH tercapai untuk domain pendek -- kriterianya mati tanpa error dan
    skor DGA selalu kekurangan satu poin. Dibagi maksimum teoretisnya supaya
    sebanding antar panjang domain.
    """
    if len(label) < 2:
        return 0.0
    return calculate_entropy(label) / math.log2(len(label))


def longest_label(domain: str) -> str:
    """
    Label paling panjang, BUKAN domain.split('.')[0].

    'www.google.com'.split('.')[0] == 'www' -- yang dinilai jadi 'www' bukan
    'google', dan skor seluruh domain bersubdomain jadi tidak ada artinya.
    """
    labels = [l for l in domain.lower().strip(".").split(".") if l and l != "www"]
    if not labels:
        return ""
    return max(labels[:-1] or labels, key=len)


def max_consonant_streak(text: str) -> int:
    """Domain DGA sering punya deretan konsonan berurutan tidak wajar."""
    streak = longest = 0
    for char in text.lower():
        if char.isalpha() and char not in VOWELS:
            streak += 1
            longest = max(longest, streak)
        else:
            streak = 0
    return longest


def score_domain(domain: str) -> dict:
    base = longest_label(domain)
    entropy = normalized_entropy(base)
    consonants = max_consonant_streak(base)
    uncommon_tld = domain.lower().endswith(UNCOMMON_TLDS)
    digit_heavy = base.isdigit()
    score = int(entropy > 0.85) + int(consonants > 4) + int(uncommon_tld) + int(digit_heavy)
    return {
        "domain": domain,
        "label_scored": base,
        "entropy_normalized": round(entropy, 2),
        "max_consonant_streak": consonants,
        "uncommon_tld": uncommon_tld,
        "all_digits": digit_heavy,
        "dga_suspicion_score": score,   # 0-4
    }


def detect_dga_pattern(domains: list[str]) -> list[dict]:
    """Skor tiap domain, urut dari yang paling mencurigakan."""
    seen, results = set(), []
    for domain in domains:
        if domain and domain not in seen:
            seen.add(domain)
            results.append(score_domain(domain))
    return sorted(results, key=lambda r: -r["dga_suspicion_score"])
