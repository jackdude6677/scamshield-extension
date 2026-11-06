"""Domain impersonation detection utilities.

Provides :func:`is_suspicious` which flags look‑alike, typosquat, and homograph domains.
"""
import re
from urllib.parse import urlparse

# Load public suffix list (PSL) from bundled file or internet fallback.
# For simplicity, embed a minimal list; real implementation would fetch.
_PUBLIC_SUFFIXES = {
    "com",
    "org",
    "net",
    "co.uk",
    "io",
    "gov",
    "edu",
}

def _get_effective_tld(domain: str) -> str:
    """Return the effective top‑level domain (eTLD) for a given domain.
    Simple lookup using the minimal public suffix set.
    """
    parts = domain.lower().split('.')
    for i in range(len(parts)):
        candidate = '.'.join(parts[i:])
        if candidate in _PUBLIC_SUFFIXES:
            return candidate
    # fallback to last part
    return parts[-1]

def _strip_etld(domain: str) -> str:
    """Return the domain without its eTLD.
    Example: "example.co.uk" -> "example".
    """
    etld = _get_effective_tld(domain)
    return domain[: -len(etld) - 1] if domain.endswith('.' + etld) else domain

def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance (iterative, O(len(a)*len(b)))."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j-1] + 1, prev[j-1] + cost)
        prev = cur
    return prev[-1]

def _is_homograph(domain: str) -> bool:
    """Detect simple homograph attacks using Unicode confusables.
    This implementation checks for non‑ASCII characters or punycode prefixes.
    """
    if domain.startswith('xn--'):
        return True
    try:
        domain.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True

def is_suspicious(url: str, *, threshold: int = 2) -> bool:
    """Return True if the domain looks suspicious.

    Checks performed:
    * Non‑ASCII characters (homograph).
    * Levenshtein distance to a known safe list (hard‑coded for demo).
    * Simple look‑alike patterns like repeated characters.
    """
    try:
        hostname = urlparse(url).hostname or url
    except Exception:
        hostname = url
    if not hostname:
        return False
    # Strip port if present
    hostname = hostname.split(':')[0]
    # Lowercase for checks
    hostname = hostname.lower()
    # Homograph detection
    if _is_homograph(hostname):
        return True
    # Remove eTLD to get the label part
    label = _strip_etld(hostname)
    # Simple look‑alike: repeated characters like "g00gle"
    if re.search(r'(.)\1{2,}', label):
        return True
    # Compare against safe list
    safe_domains = ["google.com", "paypal.com", "amazon.com", "facebook.com"]
    for safe in safe_domains:
        dist = _levenshtein(label, _strip_etld(safe))
        if 0 < dist <= threshold:
            return True
    return False

__all__ = ["is_suspicious"]
