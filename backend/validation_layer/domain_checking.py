"""
Domain checking utilities focused on phishing indicators.

Heuristics implemented:
- Unicode usage (IDN/punycode, mixed scripts, bidi/zero-width controls)
- IDN homograph detection via confusable-skeleton comparison
- Homoglyph/typosquatting proximity to known or trusted domains
- Suspicious TLDs often abused in phishing
- Excessive subdomains and label/domain length issues
- DNS presence (A/AAAA, MX) and DMARC record presence

Public entry points:
- analyze_domain(domain: str, trusted_domains: list[str] | None = None,
                 allowlist: list[str] | None = None, blocklist: list[str] | None = None) -> dict
- extract_domain_from_address(addr_or_header: str) -> str | None
- normalize_domain(domain: str) -> tuple[str, bool]
- domain_skeleton(domain: str) -> str
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple
import re
import socket
import unicodedata
from email.utils import parseaddr

try:
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore
except Exception:  # pragma: no cover - dnspython may not be available during some runs
    dns = None  # type: ignore


# Characters that can hide in domains
ZERO_WIDTH_CHARS: Set[str] = {
    "\u200B",  # zero width space
    "\u200C",  # zero width non-joiner
    "\u200D",  # zero width joiner
    "\u2060",  # word joiner
}

BIDI_CONTROL_CHARS: Set[str] = {
    "\u202A",  # LRE
    "\u202B",  # RLE
    "\u202D",  # LRO
    "\u202E",  # RLO
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
}

DOT_VARIANTS: Set[str] = {
    "\u3002",  # ideographic full stop
    "\uFF0E",  # fullwidth full stop
    "\uFF61",  # halfwidth ideographic full stop
    "\u2024",  # one dot leader
}

# Confusable mapping (subset) for IDN homograph detection
CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u0455": "s",  # ѕ
    "\u04cf": "l",  # ӏ
    # Greek → Latin (selected)
    "\u03bf": "o",  # ο
    "\u039f": "o",  # Ο
    "\u0391": "a",  # Α
    "\u0395": "e",  # Ε
    "\u0397": "h",  # Η
    "\u0399": "i",  # Ι
    "\u039a": "k",  # Κ
    "\u039c": "m",  # Μ
    "\u039d": "n",  # Ν
    "\u03a1": "p",  # Ρ
    "\u03a4": "t",  # Τ
    "\u03a7": "x",  # Χ
    "\u03a5": "y",  # Υ
    "\u03b1": "a",  # α
    "\u03b5": "e",  # ε
    "\u03b9": "i",  # ι
    "\u03ba": "k",  # κ
    "\u03bd": "n",  # ν
    "\u03c1": "p",  # ρ
    "\u03c4": "t",  # τ
    "\u03c5": "y",  # υ
    "\u03c7": "x",  # χ
}

# ASCII lookalikes used by typosquatters
ASCII_CONFUSABLES: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "8": "b",
}

# TLDs with high abuse rates or confusion potential (non-exhaustive)
SUSPICIOUS_TLDS: Set[str] = {
    "zip",
    "mov",
    "ru",
    "su",
    "cn",
    "tk",
    "ml",
    "cf",
    "gq",
    "ga",
    "xyz",
    "top",
    "club",
    "click",
    "work",
    "link",
    "live",
    "cam",
    "rest",
    "men",
    "bid",
}

# Common brands to detect obvious typosquats when no trusted_domains supplied
COMMON_BRANDS: Set[str] = {
    "google.com",
    "microsoft.com",
    "outlook.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "paypal.com",
    "amazon.com",
    "meta.com",
    "facebook.com",
    "whatsapp.com",
    "github.com",
}


def extract_domain_from_address(addr_or_header: str) -> Optional[str]:
    """Extract domain from an email address or From header string."""
    if not addr_or_header:
        return None
    _, email_addr = parseaddr(addr_or_header)
    if not email_addr or "@" not in email_addr:
        return None
    domain = email_addr.split("@", 1)[1].strip().strip(".")
    return domain.lower() or None


def _idna_ascii(domain: str) -> Tuple[str, bool]:
    """Return (ascii_idna, is_punycode).

    Uses Python's IDNA codec. Non-ASCII returns punycode with xn-- prefix.
    """
    try:
        ascii_idna = domain.encode("idna").decode("ascii")
    except Exception:
        # If it cannot be encoded, keep original as best-effort
        return domain, False
    return ascii_idna, (ascii_idna != domain)


def _has_unicode(domain: str) -> bool:
    return any(ord(c) > 127 for c in domain)


def _has_zero_width(domain: str) -> bool:
    return any(ch in domain for ch in ZERO_WIDTH_CHARS)


def _has_bidi_controls(domain: str) -> bool:
    return any(ch in domain for ch in BIDI_CONTROL_CHARS)


def _has_dot_variants(domain: str) -> bool:
    return any(ch in domain for ch in DOT_VARIANTS)


def _script_of_char(ch: str) -> str:
    # Very light heuristic: categorize by Unicode name prefix
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    for script in ("LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC", "DEVANAGARI", "CJK", "HIRAGANA", "KATAKANA"):
        if script in name:
            return script
    return "OTHER"


def _has_mixed_scripts(label: str) -> bool:
    scripts = { _script_of_char(c) for c in label if c.isalpha() }
    scripts.discard("OTHER")
    return len(scripts) > 1


def _levenshtein(a: str, b: str, max_dist: int = 2) -> int:
    """Classic Levenshtein distance with early abort."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        # small optimization: only compute window around diagonal
        start = max(1, i - max_dist)
        end = min(len(b), i + max_dist)
        for j in range(1, len(b) + 1):
            if j < start or j > end:
                cur.append(max_dist + 1)
                continue
            cost = 0 if ca == b[j - 1] else 1
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + cost))
        prev = cur
        if min(prev) > max_dist:
            return max_dist + 1
    return prev[-1]


def _second_level_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def _tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if len(parts) > 1 else ""


def _sld_label(domain: str) -> str:
    """Return the second-level label (example from example.com)."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _confusable_skeleton(label: str) -> str:
    """Best-effort confusable skeleton for homograph detection.

    Normalizes with NFKC, lowercases, maps common confusables and keeps only [a-z0-9-].
    """
    if not label:
        return ""
    s = unicodedata.normalize("NFKC", label).lower()
    out: list[str] = []
    for ch in s:
        mapped = CONFUSABLES.get(ch, ch)
        mapped = ASCII_CONFUSABLES.get(mapped, mapped)
        if ("a" <= mapped <= "z") or ("0" <= mapped <= "9") or mapped == "-":
            out.append(mapped)
    return "".join(out)


def _domain_skeleton(domain: str) -> str:
    """Compute a confusable-resistant skeleton for a full domain (per label)."""
    if not domain:
        return ""
    return ".".join(_confusable_skeleton(lbl) for lbl in domain.split(".") if lbl)


def _dns_query(name: str, rtype: str) -> bool:
    if dns is None:
        # Fallback best-effort using socket for A only
        if rtype in {"A", "AAAA"}:
            try:
                socket.getaddrinfo(name, 0)
                return True
            except Exception:
                return False
        return False
    try:
        resolver = dns.resolver.Resolver()  # type: ignore
        resolver.lifetime = 2.0  # total timeout
        resolver.timeout = 1.5
        answers = resolver.resolve(name, rtype)
        return bool(answers)
    except dns.exception.DNSException:  # type: ignore
        return False


def _has_mx(domain: str) -> bool:
    return _dns_query(domain, "MX")


def _has_a_or_aaaa(domain: str) -> bool:
    return _dns_query(domain, "A") or _dns_query(domain, "AAAA")


def _has_dmarc(domain: str) -> bool:
    return _dns_query(f"_dmarc.{domain}", "TXT")


# Public helpers
def normalize_domain(domain: str) -> Tuple[str, bool]:
    """Return (ascii_idna, is_punycode) for a domain string."""
    domain = (domain or "").strip().strip(".").lower()
    return _idna_ascii(domain)


def domain_skeleton(domain: str) -> str:
    """Return a confusable-resistant skeleton for the given domain."""
    ascii_idna, _ = normalize_domain(domain)
    return _domain_skeleton(ascii_idna)


@dataclass
class DomainAnalysis:
    domain: str
    ascii_domain: str
    is_punycode: bool
    flags: dict
    reasons: List[str]
    risk_score: int


def analyze_domain(
    domain: str,
    trusted_domains: Optional[Iterable[str]] = None,
    allowlist: Optional[Iterable[str]] = None,
    blocklist: Optional[Iterable[str]] = None,
) -> dict:
    """Analyze a domain and return phishing-oriented indicators.

    risk_score is a simple additive score; callers should interpret with context.
    """
    reasons: List[str] = []
    flags = {
        "has_unicode": False,
        "has_bidi_controls": False,
        "has_zero_width": False,
        "has_dot_variants": False,
        "mixed_scripts": False,
        "suspicious_tld": False,
        "excessive_subdomains": False,
        "long_label": False,
       "long_domain": False,
        "dns_a_or_aaaa": False,
        "dns_mx": False,
        "dmarc_present": False,
        "homoglyph_or_typosquat": False,
        "idn_homograph": False,
        "allowlisted": False,
        "blocklisted": False,
    }

    dom = (domain or "").strip().strip(".")
    dom = re.sub(r"[\s\u00A0]+", "", dom)  # remove normal and non-breaking spaces
    dom_lc = dom.lower()

    ascii_idna, is_puny = _idna_ascii(dom_lc)
    domain_skeleton = _domain_skeleton(ascii_idna)

    # Unicode and control characters
    if _has_unicode(dom_lc):
        flags["has_unicode"] = True
        reasons.append("Domain uses non-ASCII characters (IDN)")
    if _has_bidi_controls(dom_lc):
        flags["has_bidi_controls"] = True
        reasons.append("Domain contains bidirectional control characters")
    if _has_zero_width(dom_lc):
        flags["has_zero_width"] = True
        reasons.append("Domain contains zero-width characters")
    if _has_dot_variants(dom_lc):
        flags["has_dot_variants"] = True
        reasons.append("Domain contains dot lookalike characters")

    # Script mixing per label
    labels = re.split(r"[\.\u3002\uFF0E\uFF61\u2024]", dom_lc)
    if any(_has_mixed_scripts(lbl) for lbl in labels if lbl):
        flags["mixed_scripts"] = True
        reasons.append("Domain labels contain mixed Unicode scripts")

    # TLD & structure
    tld = _tld(ascii_idna)
    if tld in SUSPICIOUS_TLDS:
        flags["suspicious_tld"] = True
        reasons.append(f"Suspicious TLD: .{tld}")

    if ascii_idna.count(".") >= 4:  # e.g., a.b.c.d.example.tld
        flags["excessive_subdomains"] = True
        reasons.append("Excessive subdomains")

    if any(len(lbl) > 63 for lbl in ascii_idna.split(".")):
        flags["long_label"] = True
        reasons.append("Label exceeds 63 characters")
    if len(ascii_idna) > 253:
        flags["long_domain"] = True
        reasons.append("Domain exceeds 253 characters")

    # Punycode indicator
    if is_puny or ascii_idna.startswith("xn--"):
        flags["has_unicode"] = True
        reasons.append("Punycode (IDN) domain")

    # DNS presence
    if _has_a_or_aaaa(ascii_idna):
        flags["dns_a_or_aaaa"] = True
    if _has_mx(ascii_idna):
        flags["dns_mx"] = True
    if _has_dmarc(ascii_idna):
        flags["dmarc_present"] = True

    # Homoglyph/typosquat detection against trusted or common brands
    sld = _second_level_domain(ascii_idna)
    sld_label = _sld_label(ascii_idna)
    sld_skel = _confusable_skeleton(sld_label)
    candidates = set(COMMON_BRANDS)
    if trusted_domains:
        candidates.update(d.lower() for d in trusted_domains)
    for ref in candidates:
        ref_sld = _second_level_domain(ref)
        ref_label = _sld_label(ref_sld)
        ref_skel = _confusable_skeleton(ref_label)
        if sld_skel and ref_skel and sld_skel == ref_skel and sld_label != ref_label:
            flags["homoglyph_or_typosquat"] = True
            flags["idn_homograph"] = True
            reasons.append(f"Confusable IDN homograph of {ref_label}")
            break
        if _levenshtein(sld, ref_sld, max_dist=2) <= 2 and sld != ref_sld:
            flags["homoglyph_or_typosquat"] = True
            reasons.append(f"Looks similar to {ref_sld}")
            break

    # Compare normalized skeletons to allowlist/blocklist
    allow_match = None
    block_match = None
    if blocklist:
        for b in blocklist:
            try:
                b_ascii, _ = _idna_ascii((b or "").strip().lower())
                if _domain_skeleton(b_ascii) == domain_skeleton or _confusable_skeleton(_sld_label(b_ascii)) == sld_skel:
                    block_match = b
                    break
            except Exception:
                continue
    if allowlist and not block_match:
        for a in allowlist:
            try:
                a_ascii, _ = _idna_ascii((a or "").strip().lower())
                if _domain_skeleton(a_ascii) == domain_skeleton or _confusable_skeleton(_sld_label(a_ascii)) == sld_skel:
                    allow_match = a
                    break
            except Exception:
                continue
    if block_match:
        flags["blocklisted"] = True
        reasons.append(f"Skeleton matches blocklist: {block_match}")
    if allow_match:
        flags["allowlisted"] = True
        reasons.append(f"Skeleton matches allowlist: {allow_match}")

    # Compute a simple risk score
    score = 0
    scoring = {
        "has_bidi_controls": 30,
        "has_zero_width": 25,
        "has_dot_variants": 15,
        "mixed_scripts": 25,
        "has_unicode": 10,
        "suspicious_tld": 15,
        "excessive_subdomains": 10,
        "long_label": 5,
        "long_domain": 5,
        "homoglyph_or_typosquat": 25,
    }
    if flags.get("idn_homograph"):
        score += 30
    for k, w in scoring.items():
        if flags.get(k):
            score += w

    # Slight risk reduction if domain has MX + DMARC
    if flags["dns_mx"] and flags["dmarc_present"]:
        score = max(0, score - 10)

    list_status = "none"
    if flags["blocklisted"]:
        list_status = "block"
    elif flags["allowlisted"]:
        list_status = "allow"

    return {
        "domain": dom_lc,
        "ascii_domain": ascii_idna,
        "is_punycode": bool(is_puny or ascii_idna.startswith("xn--")),
        "skeleton": domain_skeleton,
        "sld_skeleton": sld_skel,
        "flags": flags,
        "reasons": reasons,
        "list": {
            "status": list_status,
            "allow_match": allow_match,
            "block_match": block_match,
            "passes": not flags["blocklisted"],
        },
        "risk_score": int(min(100, score)),
    }
