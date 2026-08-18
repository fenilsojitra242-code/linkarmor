"""
utils.py — Feature extraction and normalization pipeline for Phishing URL Detection
Mirrors the preprocessing used during model training with production-grade normalization.
"""

import re
import math
from urllib.parse import urlparse

# ── Shortening services known to be abused by phishers ──────────────────────
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "tiny.cc", "rb.gy", "cutt.ly", "shorte.st",
    "bc.vc", "clck.ru", "url.ie", "u.to", "v.gd", "lnkd.in", "db.tt",
    "qr.ae", "po.st", "1url.com", "tweez.me", "su.pr", "twit.ac", "ff.im",
    "short.to", "tr.im", "vi.nl", "x.co"
}

# ── Keywords that commonly appear in phishing URLs ───────────────────────────
SENSITIVE_WORDS = {
    "login", "signin", "sign-in", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "credential", "wallet", "paypal",
    "ebay", "amazon", "apple", "microsoft", "google", "facebook", "instagram",
    "support", "helpdesk", "refund", "suspension", "alert", "urgent",
    "billing", "invoice", "webscr", "cmd", "dispatch", "authorize"
}

# ── Patterns associated with Piracy, Adware & Malvertising Mirror Hubs ────────
PIRACY_PATTERNS = [
    r"hdhub", r"123movies?", r"fmovies", r"filmy", r"tamilrockers", r"torrent",
    r"camrip", r"dvdrip", r"watchfree", r"freemovies?", r"yts", r"rarbg",
    r"piratebay", r"mp4moviez", r"moviesflix", r"bolly4u", r"khatrimaza",
    r"pagalworld", r"worldfree4u", r"skymovies", r"vegamovies", r"cinevood",
    r"ibomma", r"tamilmv", r"movierulz", r"crazy4tv", r"todaypk", r"keygen",
    r"crackexe", r"warez", r"free-download-full", r"apkmod", r"modapk"
]
PIRACY_REGEX = re.compile("|".join(PIRACY_PATTERNS), re.IGNORECASE)

# ── Patterns associated with Adult / 18+ / Sensitive Content ───────────────────
ADULT_PATTERNS = [
    r"adult", r"porn", r"xxx", r"sex", r"erotic", r"nsfw", r"fetish",
    r"escort", r"camgirl", r"stripchat", r"onlyfans", r"redtube", r"xvideos",
    r"pornhub", r"youporn", r"brazzers", r"hentai", r"xhamster"
]
ADULT_REGEX = re.compile("|".join(ADULT_PATTERNS), re.IGNORECASE)


def is_piracy_or_malware_hub(url: str) -> bool:
    """Return True if URL matches known dangerous piracy/adware mirror patterns."""
    raw = normalize_url(url)
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        return bool(PIRACY_REGEX.search(host) or PIRACY_REGEX.search(path))
    except Exception:
        return False


def is_adult_content(url: str) -> bool:
    """Return True if URL is an adult/18+ content domain."""
    raw = normalize_url(url)
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        return bool(ADULT_REGEX.search(host) or ADULT_REGEX.search(path))
    except Exception:
        return False

# ── Global Top Trusted Authoritative Domains Whitelist ───────────────────────
TRUSTED_DOMAINS = {
    "localhost", "127.0.0.1", "0.0.0.0",
    "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de",
    "youtube.com", "youtu.be", "gmail.com",
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com",
    "twitter.com", "x.com", "t.co",
    "microsoft.com", "live.com", "office.com", "bing.com", "azure.com", "github.com", "gitlab.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com",
    "wikipedia.org", "wikimedia.org",
    "netflix.com", "spotify.com", "linkedin.com", "reddit.com",
    "stackoverflow.com", "stackexchange.com",
    "openai.com", "chatgpt.com", "anthropic.com", "cloudflare.com",
    "medium.com", "quora.com", "pinterest.com", "tiktok.com", "yahoo.com",
    "zoom.us", "dropbox.com", "canva.com", "figma.com", "notion.so",
    "adobe.com", "salesforce.com", "slack.com", "atlassian.com"
}


def normalize_url(url: str) -> str:
    """Ensure standard scheme and clean formatting."""
    raw = (url or "").strip()
    if not raw:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw = "https://" + raw
    # Automatically normalize http:// to https:// for standard named domains (excluding raw IP attacks)
    elif raw.startswith("http://") and not re.match(r"^http://(\d{1,3}\.){3}\d{1,3}", raw):
        raw = "https://" + raw[7:]
    return raw


def get_registered_domain(hostname: str) -> str:
    """Extract registered apex domain (e.g., accounts.google.com -> google.com)."""
    if not hostname:
        return ""
    # Strip port if present
    host = hostname.split(":")[0].lower()
    if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        # Handle two-part TLDs like .co.uk, .co.in
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "edu", "net", "ac"} and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host


def is_trusted_domain(url: str) -> bool:
    """
    Check if the URL belongs to a verified authoritative global domain or local machine.
    Safely rejects deceptive trick domains (e.g. google.com.fake.com or google-login.com).
    """
    raw = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        
        # Local loopback / development server
        if hostname in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return True
            
        # Immediate exclusions: raw IP, @ symbol in netloc, or deceptive 'https' in host
        if _has_ip_address(hostname) or "@" in (parsed.netloc or "") or _https_in_hostname(hostname):
            return False
            
        reg_domain = get_registered_domain(hostname)
        return reg_domain in TRUSTED_DOMAINS
    except Exception:
        return False


def check_domain_dns(url: str) -> tuple:
    """
    Perform a quick live DNS resolution check.
    Returns (is_valid: bool, ip_or_error: str).
    """
    import socket
    raw = normalize_url(url)
    try:
        parsed = urlparse(raw)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False, "Invalid URL"
        if hostname in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return True, "127.0.0.1"
        
        # Fast DNS lookup with 2 second timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            ip = socket.gethostbyname(hostname)
            return True, ip
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception as exc:
        return False, str(exc)


def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _has_ip_address(hostname: str) -> int:
    """Return 1 if the hostname is a raw IPv4 or IPv6 address."""
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")
    return int(bool(ipv4.match(hostname) or ipv6.match(hostname)))


def _count_subdomains(hostname: str) -> int:
    """Number of subdomains (parts before the registered domain)."""
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def _is_shortened(hostname: str) -> int:
    """Return 1 if hostname matches a known URL-shortening service."""
    return int(hostname.lower() in SHORTENING_SERVICES)


def _has_sensitive_word(url: str) -> int:
    """Return 1 if the URL contains any phishing-associated keyword."""
    url_lower = url.lower()
    return int(any(word in url_lower for word in SENSITIVE_WORDS))


def _https_in_hostname(hostname: str) -> int:
    """Return 1 if 'https' literally appears inside the hostname (deceptive trick)."""
    return int("https" in hostname.lower())


def extract_features(url: str) -> list:
    """
    Extract the 27 features used during model training.
    Normalizes scheme (defaults to https://) and canonicalizes inputs.
    """
    raw = normalize_url(url)

    try:
        parsed = urlparse(raw)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
    except Exception:
        hostname = path = query = fragment = ""

    # Canonicalize for feature extraction matching Kaggle training expectations:
    # In training, benign sites had 'www.' and 2 dots (count_dot=2, num_subdomains=1)
    effective_url = raw
    effective_host = hostname
    if hostname and not hostname.startswith("www.") and len(hostname.split(".")) == 2 and not _has_ip_address(hostname):
        effective_host = "www." + hostname
        effective_url = raw.replace(hostname, effective_host, 1)

    # ── Lengths ──────────────────────────────────────────────────────────────
    url_length = len(effective_url)
    hostname_length = len(effective_host)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    # ── Structural ────────────────────────────────────────────────────────────
    num_subdomains = _count_subdomains(effective_host)
    path_depth = path.count("/")

    # ── Character counts (over the full URL) ─────────────────────────────────
    count_dot = effective_url.count(".")
    count_hyphen = effective_url.count("-")
    count_underscore = effective_url.count("_")
    count_slash = effective_url.count("/")
    count_question = effective_url.count("?")
    count_equals = effective_url.count("=")
    count_at = effective_url.count("@")
    count_ampersand = effective_url.count("&")
    count_exclaim = effective_url.count("!")
    count_hash = effective_url.count("#")
    count_percent = effective_url.count("%")
    count_plus = effective_url.count("+")

    # ── Digit / letter composition ────────────────────────────────────────────
    digit_count = sum(c.isdigit() for c in effective_url)
    letter_count = sum(c.isalpha() for c in effective_url)
    digit_letter_ratio = (
        digit_count / letter_count if letter_count > 0 else 0.0
    )

    # ── Boolean signals ───────────────────────────────────────────────────────
    has_ip = _has_ip_address(hostname)
    has_sensitive_word = _has_sensitive_word(raw)
    is_shortened = _is_shortened(hostname)
    https_in_hostname_ = _https_in_hostname(hostname)
    uses_https = int(parsed.scheme.lower() == "https")

    return [
        url_length, hostname_length, path_length, query_length,
        fragment_length, num_subdomains, path_depth,
        count_dot, count_hyphen, count_underscore, count_slash,
        count_question, count_equals, count_at, count_ampersand,
        count_exclaim, count_hash, count_percent, count_plus,
        digit_count, letter_count, digit_letter_ratio,
        has_ip, has_sensitive_word, is_shortened,
        https_in_hostname_, uses_https,
    ]


FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "fragment_length", "num_subdomains", "path_depth",
    "count_dot", "count_hyphen", "count_underscore", "count_slash",
    "count_question", "count_equals", "count_at", "count_ampersand",
    "count_exclaim", "count_hash", "count_percent", "count_plus",
    "digit_count", "letter_count", "digit_letter_ratio",
    "has_ip", "has_sensitive_word", "is_shortened",
    "https_in_hostname", "uses_https",
]


def extract_evidence_chips(url: str) -> list:
    """Extract human-readable forensic evidence chips for UI explainability."""
    raw = normalize_url(url)
    chips = []
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
    except Exception:
        host = path = ""

    if _has_ip_address(host):
        chips.append({"name": "Raw IP Host", "type": "threat"})
    if _has_sensitive_word(raw):
        chips.append({"name": "Credential Keyword", "type": "warning"})
    if _is_shortened(host):
        chips.append({"name": "URL Shortener Mask", "type": "warning"})
    if _https_in_hostname(host):
        chips.append({"name": "Deceptive HTTPS Subdomain", "type": "threat"})
    if _count_subdomains(host) > 1:
        chips.append({"name": "Multiple Subdomains", "type": "warning"})
    if len(host) > 28:
        chips.append({"name": "Abnormal Host Length", "type": "warning"})
    if raw.count("-") >= 2:
        chips.append({"name": "Multiple Hyphens", "type": "warning"})
    if "@" in raw:
        chips.append({"name": "Suspicious @ Token", "type": "threat"})
    if is_piracy_or_malware_hub(url):
        chips.append({"name": "Piracy / Torrent Signature", "type": "threat"})
    if is_adult_content(url):
        chips.append({"name": "18+ Adult Signature", "type": "sensitive"})
    if is_trusted_domain(url):
        chips.append({"name": "Authoritative Top Domain", "type": "safe"})
    
    if not chips:
        chips.append({"name": "Standard Lexical Structure", "type": "safe"})
        chips.append({"name": "Clean Path Pattern", "type": "safe"})

    return chips


def extract_url_dossier(url: str) -> dict:
    """Extract complete detailed forensic breakdown of a URL for exhaustive UI reporting."""
    from urllib.parse import parse_qs
    raw = normalize_url(url)
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        hostname = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        params = {k: v if len(v) > 1 else v[0] for k, v in parse_qs(query).items()}
    except Exception:
        scheme = "https"
        hostname = url
        port = 443
        path = "/"
        query = ""
        fragment = ""
        params = {}

    reg_domain = get_registered_domain(hostname)
    subdomain = ""
    if hostname and reg_domain and hostname != reg_domain:
        subdomain = hostname[:-len(reg_domain)].rstrip(".")
    
    entropy_val = calculate_entropy(raw)
    dns_valid, dns_detail = check_domain_dns(url)
    
    # Matching sensitive words
    found_keywords = [w for w in SENSITIVE_WORDS if w in raw.lower()]
    
    # Character breakdown
    special_chars_count = sum(raw.count(c) for c in "@-_?=&!#%+~/:.")
    digit_count = sum(c.isdigit() for c in raw)
    letter_count = sum(c.isalpha() for c in raw)
    ratio = round(digit_count / letter_count, 3) if letter_count > 0 else 0.0

    raw_features = extract_features(url)
    features_map = dict(zip(FEATURE_NAMES, raw_features))

    return {
        "raw_url": url,
        "canonical_url": raw,
        "scheme": scheme.upper(),
        "is_https": scheme.lower() == "https",
        "hostname": hostname,
        "registered_domain": reg_domain,
        "subdomain": subdomain if subdomain else "None",
        "subdomain_depth": _count_subdomains(hostname),
        "port": port,
        "path": path,
        "path_depth": path.count("/"),
        "query_string": query if query else "None",
        "query_params": params,
        "param_count": len(params),
        "fragment": fragment if fragment else "None",
        "url_length": len(raw),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "entropy": entropy_val,
        "special_chars_count": special_chars_count,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "digit_letter_ratio": ratio,
        "has_ip_address": bool(_has_ip_address(hostname)),
        "is_shortened": bool(_is_shortened(hostname)),
        "https_in_hostname": bool(_https_in_hostname(hostname)),
        "matched_keywords": found_keywords,
        "dns_valid": dns_valid,
        "dns_resolved_ip": dns_detail if dns_valid else "DNS Failed / Unresolved",
        "features_map": features_map,
    }



