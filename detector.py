import whois
import re
import time
import tldextract
import ipaddress
import io
import threading
import contextlib
import logging
from datetime import datetime
from urllib.parse import unquote, urlsplit
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from collections import namedtuple

from domain_info import get_domain_information

from data.brands import POPULAR_DOMAINS
from data.suspicious_tlds import SUSPICIOUS_TLDS
from data.url_shorteners import URL_SHORTENERS
from data.hosting_domains import KNOWN_INFRA_DOMAINS
from data.phishing_keywords import PHISHING_KEYWORDS

LOGGER = logging.getLogger(__name__)

# Use the bundled snapshot instead of fetching the public suffix list
# over the network on every run (avoids slow/failing HTTP calls + noisy tracebacks)
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Set to True if you want to see WHY a WHOIS lookup failed (timeout, no data, etc.)
VERBOSE = False

# Matches a leading URI scheme like "http:", "javascript:", "ftp:" etc.
_SCHEME_PATTERN = re.compile(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):")

# Fix 6: simple in-memory WHOIS cache to avoid re-querying the same domain
# on every scan. TTL is intentionally short-lived (1 hour) since this is a
# plain dict, not a persistent cache - it resets whenever the app restarts.
_whois_cache = {}
_WHOIS_CACHE_TTL_SECONDS = 3600


def levenshtein_distance(a, b):
    """Measures how many single-character edits it takes to turn a into b."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def looks_like_gibberish(domain):
    """Flags domains that look randomly generated rather than human-chosen.

    Real words rarely have more than 2-3 consonants in a row (brand names like
    'microsoft', 'facebook', 'instagram' all stay at 2-3). Random strings
    routinely hit 4+.
    """
    if len(domain) < 6:
        return False

    vowels = set("aeiou")
    max_consonant_run = 0
    current_run = 0
    for ch in domain.lower():
        if ch.isalpha() and ch not in vowels:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0

    return max_consonant_run >= 4


def _tokenize(text):
    """Splits text into lowercase alphanumeric tokens on any separator
    (., -, /, ?, =, _, etc). Used by the keyword/brand-substring checks to
    replace raw substring matching with token-boundary-aware matching.
    """
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _token_matches(tokens, word):
    """True if any token equals, starts with, or ends with `word`."""
    return any(tok == word or tok.startswith(word) or tok.endswith(word) for tok in tokens)


def _is_ip_address(hostname):
    """True if hostname is a literal IPv4 or IPv6 address (not a domain
    name). Uses the stdlib ipaddress module rather than a regex, so this
    correctly catches IPv6 too, not just IPv4.
    """
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


ParsedURL = namedtuple("ParsedURL", [
    "scheme", "username", "password", "hostname",
    "subdomain", "domain", "suffix", "full_domain",
    "path", "query",
])


def _parse_url_components(url):
    """Parses `url` (already scheme-normalized by the caller) into its
    structural pieces: urllib.parse.urlsplit() handles the URI-level split
    (scheme, userinfo, hostname, path, query), and tldextract is run only
    on the isolated hostname (not the whole URL string) to get the DNS-level
    breakdown (subdomain, domain, suffix).

    Centralizing this here means every detection rule below reads from ONE
    parsed representation instead of each rule re-scanning the raw url
    string in its own way - e.g. the HTTPS check compares parsed.scheme
    directly rather than doing a string-prefix check, and the keyword check
    scans only hostname+path+query rather than the entire raw URL.
    """
    split = urlsplit(url)
    hostname = (split.hostname or "").lower()

    extracted = _tld_extractor(hostname)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    full_domain = f"{domain}.{suffix}" if suffix else domain

    return ParsedURL(
        scheme=(split.scheme or "").lower(),
        username=split.username or "",
        password=split.password or "",
        hostname=hostname,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        full_domain=full_domain,
        path=split.path or "",
        query=split.query or "",
    )


# --- Redesigned typosquat detection -----------------------------------------
#
# Generic TLDs are excluded from the "same TLD" candidate filter, since
# typosquats commonly and deliberately swap to a different (often cheaper or
# more suspicious) generic TLD while keeping the brand name itself nearly
# identical (e.g. paypal.com -> paypa1-secure-login.xyz). Requiring an exact
# TLD match for these would eliminate one of the most common real-world
# typosquat patterns. Distinctive country-code/compound suffixes (.de,
# .com.br, .pl) are a much stronger candidate-narrowing signal precisely
# because they're rarely swapped by attackers targeting that specific brand.
_GENERIC_TYPOSQUAT_SUFFIXES = {"com", "net", "org", "info", "io", "co"}

_MIN_TYPOSQUAT_WORD_LENGTH = 4

# Minimum length a POPULAR_DOMAINS brand name must have before it's used in
# token-based substring/startswith/endswith brand matching (rule_brand_
# impersonation, rule_brand_in_username, and the punycode brand-homograph
# check below). Without this floor, a short brand name like "x" (X/Twitter)
# or "ing" (ING Bank) matches almost any token that merely happens to start
# or end with those letters - e.g. "tracking" ends with "ing", and nearly
# every domain contains an "x" somewhere. Real-world confusable brand names
# worth flagging (itau, sbi, bofa, etc.) are all >= 4 characters, so this
# costs no true-positive coverage.
_MIN_BRAND_MATCH_LENGTH = 4


def _matchable_brand_name(popular_domain):
    """Returns the brand name portion of a POPULAR_DOMAINS entry if it's
    long enough to be used safely in token matching, else None.
    """
    name = popular_domain.split(".")[0]
    return name if len(name) >= _MIN_BRAND_MATCH_LENGTH else None
_MAX_TYPOSQUAT_LENGTH_DIFFERENCE = 2

# Empirically calibrated - NOT the initially-suggested 90-95%. Every
# validated true-positive typosquat this project has confirmed sits at
# 83-89% normalized similarity (paypa1/paypal 83.3%, googgle/google 85.7%,
# sparkase/sparkasse 88.9%), while the reported false positive reddit/redhat
# sits at 66.7%. A 90-95% threshold would reject every real catch above; 82%
# sits comfortably below all of them and well above the false positive.
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.82


def _split_brand(full_domain):
    """Splits 'sparkasse.de' into ('sparkasse', 'de'), 'itau.com.br' into
    ('itau', 'com.br')."""
    parts = full_domain.split(".", 1)
    name = parts[0].lower()
    suffix = parts[1].lower() if len(parts) > 1 else ""
    return name, suffix


def _build_brand_index(popular_domains):
    """Groups brand names by first letter so lookups only scan the small
    bucket sharing that first character, not the full brand list. This is
    what satisfies 'do not compare every domain against every brand' -
    for a 500-brand list this typically narrows ~500 candidates down to
    single digits per lookup.
    """
    index = {}
    for full in popular_domains:
        name, suffix = _split_brand(full)
        if len(name) < _MIN_TYPOSQUAT_WORD_LENGTH:
            continue
        index.setdefault(name[0], []).append((name, suffix, full))
    return index


_BRAND_INDEX = _build_brand_index(POPULAR_DOMAINS)


def normalized_similarity(a, b):
    """Levenshtein distance normalized to a 0.0-1.0 similarity score (1.0 =
    identical). Normalizing by the longer string's length means the same
    raw edit distance counts for more against a short word than a long one -
    a 2-character edit on a 6-letter word is proportionally a much bigger
    change than the same edit on a 15-letter word, which is exactly what
    was missing from the old fixed-threshold raw-distance check.
    """
    if not a and not b:
        return 1.0
    distance = levenshtein_distance(a, b)
    max_len = max(len(a), len(b))
    return 1 - (distance / max_len)


def get_typosquat_candidates(word):
    """Returns only the brands worth comparing `word` against: same
    starting letter (via the prebuilt index) and within 2 characters of
    length. This is the filtering step - it keeps each check to a handful
    of comparisons instead of scanning the entire brand list.
    """
    if len(word) < _MIN_TYPOSQUAT_WORD_LENGTH:
        return []
    bucket = _BRAND_INDEX.get(word[0], [])
    return [
        (name, suffix, full) for (name, suffix, full) in bucket
        if abs(len(name) - len(word)) <= _MAX_TYPOSQUAT_LENGTH_DIFFERENCE
    ]


def find_typosquat_match(word, checked_domain_suffix):
    """Checks `word` against only its likely-candidate brands using
    normalized similarity. Returns the matched full brand domain, or None.
    """
    for name, brand_suffix, full in get_typosquat_candidates(word):
        # Same-TLD filter, applied only when the brand's own suffix is
        # distinctive (not a generic gTLD) - see comment block above.
        if brand_suffix and brand_suffix.split(".")[-1] not in _GENERIC_TYPOSQUAT_SUFFIXES:
            if checked_domain_suffix.lower() != brand_suffix:
                continue

        if word == name:
            continue  # exact match is brand reuse, not typosquatting - 9b handles that case

        similarity = normalized_similarity(word, name)
        if similarity >= TYPOSQUAT_SIMILARITY_THRESHOLD:
            return full
    return None


# Thread pool used to enforce a real wall-clock timeout on WHOIS lookups.
# whois.whois()'s own `timeout` parameter only covers the final query to the
# resolved WHOIS server - it does NOT cover the earlier IANA referral lookup
# step, which is hardcoded to a 10-second socket timeout inside the library
# itself (confirmed by reading whois/whois.py). Without this wrapper, a scan
# can still block for up to 10s regardless of the timeout value we pass in.
_whois_executor = ThreadPoolExecutor(max_workers=4)
_WHOIS_HARD_TIMEOUT_SECONDS = 3

# Some `whois` library internals (and the socket/DNS code underneath them)
# print raw error text directly - e.g. "Error trying to connect to socket:
# closing socket - [Errno 11001] getaddrinfo failed" - instead of raising a
# clean exception. That output bypasses our try/except entirely, so a
# print() guard alone (VERBOSE flag) can't stop it. sys.stdout/sys.stderr
# are process-global, not thread-local, so this lock serializes the small
# window during which they're redirected - otherwise two concurrent WHOIS
# lookups (this pool allows 4) could interleave and corrupt each other's
# redirect/restore.
_whois_output_lock = threading.Lock()


def _whois_lookup(domain_with_suffix):
    with _whois_output_lock:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            return whois.whois(domain_with_suffix, timeout=_WHOIS_HARD_TIMEOUT_SECONDS)


def check_domain_age(domain_with_suffix, verbose=False):
    """Returns age in days, or None if lookup fails. Cached per domain for
    _WHOIS_CACHE_TTL_SECONDS to avoid re-querying WHOIS on every repeated
    scan of the same domain (Fix 6).
    """
    now = time.time()
    cached = _whois_cache.get(domain_with_suffix)
    if cached is not None:
        cached_age_days, cached_at = cached
        if now - cached_at < _WHOIS_CACHE_TTL_SECONDS:
            if verbose:
                print(f"    [debug] Using cached WHOIS result for {domain_with_suffix}")
            return cached_age_days

    try:
        future = _whois_executor.submit(_whois_lookup, domain_with_suffix)
        w = future.result(timeout=_WHOIS_HARD_TIMEOUT_SECONDS)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            if verbose:
                print(f"    [debug] WHOIS returned no creation date for {domain_with_suffix}")
            _whois_cache[domain_with_suffix] = (None, now)
            return None

        age_days = (datetime.now() - creation_date).days
        _whois_cache[domain_with_suffix] = (age_days, now)
        return age_days
    except FutureTimeoutError:
        if verbose:
            print(f"    [debug] WHOIS lookup for {domain_with_suffix} exceeded {_WHOIS_HARD_TIMEOUT_SECONDS}s hard timeout")
        _whois_cache[domain_with_suffix] = (None, now)
        return None
    except Exception as e:
        if verbose:
            print(f"    [debug] WHOIS lookup failed for {domain_with_suffix}: {e}")
        # Cache the failure too - avoids hammering a slow/dead WHOIS server
        # on every request during an outage.
        _whois_cache[domain_with_suffix] = (None, now)
        return None


def get_domain_age_metadata(full_domain, verbose=False):
    """Part 3 - Public, structured wrapper around check_domain_age().

    This is the only entry point the rest of the code (and callers outside
    this module) should use for WHOIS data. It guarantees three things:

      1. No exceptions ever escape - check_domain_age() already swallows
         WHOIS/network errors internally and only prints them when
         VERBOSE/verbose is True (never by default), so this wrapper never
         raises.
      2. A timeout is always enforced - inherited from check_domain_age(),
         which hard-bounds the lookup to _WHOIS_HARD_TIMEOUT_SECONDS via the
         thread-pool future, regardless of what the underlying `whois`
         library does internally.
      3. Caching is always used - inherited from the _whois_cache TTL cache
         inside check_domain_age(), so repeated scans of the same domain
         don't re-hit the network.

    On any failure (timeout, no WHOIS data, malformed response, unreachable
    server, etc.) this degrades gracefully to a clearly-labeled "unavailable"
    result rather than raising or silently returning nothing - the caller in
    check_url() treats that as "skip the age check", never as a mid-scan
    failure that stops the rest of the analysis.
    """
    age_days = check_domain_age(full_domain, verbose=verbose)
    if age_days is None:
        return {
            "available": False,
            "age_days": None,
            "note": "Domain age unavailable",
        }
    return {
        "available": True,
        "age_days": age_days,
        "note": None,
    }


# --- Part 4: Path-analysis module -------------------------------------------
#
# Deliberately kept independent from hostname/domain analysis (typosquatting,
# brand impersonation, TLD checks, etc. above): this module inspects ONLY the
# URL path, so it works the same way regardless of what the hostname looks
# like, and its result is reported as its own separate sub-object rather than
# being folded into the hostname-based flags.

PHISHING_PATH_KEYWORDS = [
    "login", "signin", "verify", "account", "password",
    "oauth", "update", "secure", "webscr",
]

# webscr is the classic PayPal-impersonation path keyword
# (paypal.com/cgi-bin/webscr) - kept as its own literal entry since it
# doesn't tokenize into a smaller meaningful word.

_PATH_CONFIDENCE_BY_HIT_COUNT = {
    0: "none",
    1: "low",
    2: "medium",
}


def analyze_path(path, query=""):
    """Inspects only the URL path (optionally the query string too, since
    phishing keywords are just as often stuffed into query params) and
    reports suspicious phishing-style path keywords.

    Returns a dict with:
      - score:            int contribution (independent of hostname score)
      - confidence:        "none" | "low" | "medium" | "high"
      - matched_keywords:  list of matched keywords, in match order
      - reason:            human-readable explanation
    """
    searchable = unquote(f"{path}?{query}" if query else path)
    tokens = _tokenize(searchable)

    matched_keywords = [kw for kw in PHISHING_PATH_KEYWORDS if _token_matches(tokens, kw)]
    hit_count = len(matched_keywords)

    if hit_count == 0:
        return {
            "score": 0,
            "confidence": "none",
            "matched_keywords": [],
            "reason": "No suspicious phishing-style keywords found in the URL path",
        }

    score = min(hit_count, 3)
    confidence = _PATH_CONFIDENCE_BY_HIT_COUNT.get(hit_count, "high")
    shown = ", ".join(matched_keywords[:3])
    extra = f" (+{hit_count - 3} more)" if hit_count > 3 else ""
    reason = (
        f"URL path contains phishing-style keyword(s): {shown}{extra} - "
        f"commonly used in credential-harvesting or account-verification scams"
    )

    return {
        "score": score,
        "confidence": confidence,
        "scan_status": "Completed",
        "matched_keywords": matched_keywords,
        "reason": reason,
    }


# --- Part 5: Unicode / Punycode (homograph) detection -----------------------
#
# Also kept independent from the other hostname checks (typosquatting,
# brand-in-subdomain, etc.) - this only cares whether a label is Punycode
# ("xn--"-prefixed) and, if so, what it decodes to. It doesn't attempt to
# cross-reference the decoded name against the brand list; it just reports
# the possibility of a homograph attack so a human (or another rule) can
# judge it.

def _decode_punycode_label(label):
    """Decodes a single 'xn--...' DNS label to its Unicode form. Returns
    None if the label isn't valid Punycode (never raises).
    """
    if not label.lower().startswith("xn--"):
        return None
    remainder = label[4:]
    if not remainder:
        return None
    try:
        return remainder.encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return None


def analyze_punycode(hostname):
    """Detects Punycode-encoded ('xn--') labels anywhere in the hostname and
    attempts to decode them, to surface possible homograph (look-alike
    Unicode) attacks.

    Returns a dict with:
      - score:           int contribution (independent of hostname score)
      - confidence:       "none" | "low" | "high"
      - decoded_domain:   the hostname with xn-- labels decoded to Unicode,
                           or None if nothing was decodable
      - reason:           human-readable explanation
    """
    hostname = (hostname or "").lower()
    labels = [l for l in hostname.split(".") if l]
    xn_labels = [l for l in labels if l.startswith("xn--")]

    if not xn_labels:
        return {
            "score": 0,
            "confidence": "none",
            "decoded_domain": None,
            "reason": "No Punycode (xn--) labels detected in hostname",
        }

    decoded_labels = []
    any_decode_failed = False
    for label in labels:
        if label.startswith("xn--"):
            decoded = _decode_punycode_label(label)
            if decoded is None:
                any_decode_failed = True
                decoded_labels.append(label)
            else:
                decoded_labels.append(decoded)
        else:
            decoded_labels.append(label)

    if any_decode_failed:
        return {
            "score": 2,
            "confidence": "low",
            "decoded_domain": None,
            "reason": "Hostname contains a Punycode-style label ('xn--') that could not be decoded",
        }

    decoded_domain = ".".join(decoded_labels)
    reason = (
        f"Hostname is Punycode-encoded and decodes to '{decoded_domain}' - "
        f"internationalized domains can use look-alike Unicode characters to "
        f"impersonate trusted brand names (homograph attack)"
    )
    return {
        "score": 4,
        "confidence": "high",
        "decoded_domain": decoded_domain,
        "reason": reason,
    }



# =============================================================================
# WEIGHTED SCORING ENGINE (0-100)
# =============================================================================
#
# Everything below replaces the old "score += N" accumulator with a
# professional, fully rule-based weighted model. No machine learning is
# used anywhere - every number here is a hand-set weight/confidence, and
# every rule's logic is the same deterministic string/structural checks
# that existed before, just wrapped in a standardized return shape.
#
# RULE_CONFIG is the single source of truth for how much each rule is
# worth. To retune the entire engine (make typosquatting matter more,
# domain age matter less, etc.) edit ONLY the numbers below - never the
# rule functions themselves.
#
# Each rule is worth `weight` points if it fires at full (1.0) confidence.
# Weights deliberately sum to well over 100 across all rules: a single
# serious signal shouldn't auto-saturate the score, but several serious,
# independent signals firing together legitimately should (and will,
# since the total is capped at 100 in calculate_threat_score).

RULE_CONFIG = {
    "disallowed_scheme": {
        "weight": 100, "category": "critical",
        "description": "Non-HTTP(S) URI scheme (javascript:, data:, ftp:, etc.)",
    },
    "malformed_whitespace": {
        "weight": 6, "category": "structural",
        "description": "URL contains internal spaces",
    },
    "no_https": {
        "weight": 5, "category": "transport",
        "description": "Connection is not encrypted (no HTTPS)",
    },
    "ip_address_host": {
        "weight": 12, "category": "structural",
        "description": "Raw IP address used instead of a domain name",
    },
    "suspicious_tld": {
        "weight": 6, "category": "structural",
        "description": "Top-level domain commonly abused for phishing",
    },
    "url_shortener": {
        "weight": 8, "category": "structural",
        "description": "Known URL-shortening service hides the real destination",
    },
    "userinfo_present": {
        "weight": 12, "category": "deception",
        "description": "Username/password segment before '@' in the URL",
    },
    "brand_in_username": {
        "weight": 20, "category": "deception",
        "description": "Real brand name spelled out before '@' to mask the true destination",
    },
    "excessive_subdomains": {
        "weight": 4, "category": "structural",
        "description": "Three or more subdomain levels",
    },
    "excessive_hyphens": {
        "weight": 4, "category": "structural",
        "description": "Two or more hyphens in domain/subdomain",
    },
    "gibberish_domain": {
        "weight": 8, "category": "structural",
        "description": "Domain name looks randomly generated rather than a real word",
    },
    "url_length": {
        "weight": 5, "category": "structural",
        "description": "Abnormally long URL, often used to obscure the real destination",
    },
    "phishing_keywords_host": {
        "weight": 10, "category": "content",
        "description": "Phishing-style keywords in hostname/path/query",
    },
    "typosquatting": {
        "weight": 28, "category": "deception",
        "description": "Domain closely resembles a known brand (typo-distance)",
    },
    "brand_impersonation": {
        "weight": 24, "category": "deception",
        "description": "Brand name present in subdomain but domain isn't the real brand",
    },
    "domain_age": {
        "weight": 12, "category": "infrastructure",
        "description": "Recently-registered domain (WHOIS creation date)",
    },
    "path_keywords": {
        "weight": 13, "category": "content",
        "description": "Phishing-style keywords in the URL path",
    },
    "punycode_present": {
        "weight": 8, "category": "encoding",
        "description": "Hostname contains a Punycode/ACE-encoded (xn--) label",
    },
    "punycode_brand_homograph": {
        "weight": 30, "category": "encoding",
        "description": "Decoded Punycode label closely matches a known brand - confirmed homograph attack pattern",
    },
}


def _rule_result(rule_id, triggered, reason, confidence=0.0, metadata=None):
    """Builds the standardized return shape every rule function must use:
    rule_id, triggered, reason, confidence, metadata. Confidence and reason
    are normalized to 0.0/None when the rule didn't trigger, so a
    not-triggered rule can never accidentally contribute score.
    """
    try:
        normalized_confidence = min(max(float(confidence), 0.0), 1.0) if triggered else 0.0
    except (TypeError, ValueError):
        normalized_confidence = 0.0
    return {
        "rule_id": rule_id,
        "triggered": bool(triggered),
        "reason": reason if triggered else None,
        "confidence": round(normalized_confidence, 3),
        "score": 0,
        "metadata": metadata if isinstance(metadata, dict) else {},
    }


def _unavailable_rule_result(rule_id):
    """A safe module result for failed or incomplete external data."""
    result = _rule_result(rule_id, False, None)
    result.update({"score": 0, "confidence": 0.0, "reason": "Unavailable", "metadata": {}})
    return result


def _validate_rule_result(result):
    """Validate every module result before it enters score aggregation."""
    if not isinstance(result, dict) or not isinstance(result.get("rule_id"), str):
        return _unavailable_rule_result("unknown_rule")
    rule_id = result["rule_id"]
    try:
        confidence = float(result.get("confidence", 0))
    except (TypeError, ValueError):
        return _unavailable_rule_result(rule_id)
    if not 0 <= confidence <= 1:
        return _unavailable_rule_result(rule_id)
    result = dict(result)
    result["triggered"] = bool(result.get("triggered", False))
    result["confidence"] = confidence if result["triggered"] else 0.0
    result["metadata"] = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    result["reason"] = result.get("reason") if isinstance(result.get("reason"), str) else ("Unavailable" if not result["triggered"] else "Detected")
    result["score"] = round(RULE_CONFIG.get(rule_id, {}).get("weight", 0) * result["confidence"])
    return result


# The complete, documented set of fields check_url() relies on from
# get_domain_information(). Audit finding: nothing previously validated this
# dict's shape/types before using it - rule_domain_age() read straight from
# it into a numeric comparison. _validate_domain_info() closes that gap the
# same way _validate_rule_result() already does for rule dicts: no matter
# what domain_info.py returns (even if it's mid-refactor, buggy, or a
# completely different shape), this function guarantees a safe, complete
# dict before anything downstream touches it, and logs when it had to
# substitute a default.
_DOMAIN_INFO_STRING_DEFAULTS = {
    "hostname": "Unavailable", "registrable_domain": "Unavailable", "domain": "Unavailable",
    "subdomain": "Unavailable", "suffix": "Unavailable", "registrar": "Unavailable",
    "created_date": "Unavailable", "expiry_date": "Unavailable", "country": "Unavailable",
    "ip_address": "Unavailable", "hosting_provider": "Unavailable", "ssl_status": "Unavailable",
    "age_days": "Unavailable", "domain_age": "Unavailable", "expires_in": "Unavailable",
}


def _validate_domain_info(domain_info):
    """Guarantees a complete, safely-typed domain_info dict. Called at the
    check_url() boundary before domain_info is used in ANY comparison or
    passed into a rule function - this is the fix for the class of bug
    audited in this investigation (a module output being trusted and used
    in a numeric comparison without validation first).
    """
    if not isinstance(domain_info, dict):
        LOGGER.warning("get_domain_information() returned a non-dict (%r) - substituting safe defaults", type(domain_info))
        domain_info = {}

    safe = dict(_DOMAIN_INFO_STRING_DEFAULTS)
    safe["whois_available"] = False

    for key, default in _DOMAIN_INFO_STRING_DEFAULTS.items():
        value = domain_info.get(key, default)
        if key == "age_days":
            # age_days is the one field allowed to be an int (everything
            # else here is always a display string) - validate its type
            # explicitly rather than assuming domain_info.py got it right.
            if not isinstance(value, int) or isinstance(value, bool):
                if value is not None and value != default:
                    LOGGER.warning("domain_info.age_days was %r (not int) - substituting %r", value, default)
                value = default
            safe[key] = value
            continue
        if value is None or not isinstance(value, str):
            LOGGER.warning("domain_info.%s was %r (expected str) - substituting %r", key, value, default)
            value = default
        safe[key] = value

    whois_available = domain_info.get("whois_available", False)
    safe["whois_available"] = bool(whois_available) if isinstance(whois_available, (bool, int)) else False

    return safe


# --- Individual rule functions -----------------------------------------
# Each one wraps exactly the same detection logic that existed in the
# previous version of check_url() - only the return shape has changed,
# from "append to flags / add to score" into a standalone RuleResult.

def rule_disallowed_scheme(scheme):
    return _rule_result(
        "disallowed_scheme", True,
        f"Disallowed URL scheme '{scheme}:' - only http and https are supported",
        confidence=1.0, metadata={"scheme": scheme},
    )


def rule_malformed_whitespace(url):
    triggered = " " in url
    return _rule_result(
        "malformed_whitespace", triggered,
        "URL contains spaces - likely malformed or manually typed incorrectly",
        confidence=0.6,
    )


def rule_no_https(parsed):
    triggered = parsed.scheme != "https"
    return _rule_result(
        "no_https", triggered,
        "No HTTPS - connection is not encrypted",
        confidence=0.5,
    )


def rule_ip_address_host(parsed):
    triggered = _is_ip_address(parsed.hostname)
    return _rule_result(
        "ip_address_host", triggered,
        "Uses raw IP address instead of a domain name",
        confidence=0.9, metadata={"hostname": parsed.hostname},
    )


def rule_suspicious_tld(parsed):
    triggered = f".{parsed.suffix.lower()}" in SUSPICIOUS_TLDS
    return _rule_result(
        "suspicious_tld", triggered,
        "Suspicious top-level domain detected",
        confidence=0.6, metadata={"suffix": parsed.suffix},
    )


def rule_url_shortener(parsed):
    triggered = parsed.full_domain.lower() in URL_SHORTENERS
    return _rule_result(
        "url_shortener", triggered,
        "URL shortener detected - real destination is hidden",
        confidence=0.7, metadata={"full_domain": parsed.full_domain},
    )


def rule_userinfo_present(parsed):
    triggered = bool(parsed.username)
    reason = (
        f"URL contains a username before '@' - browsers ignore everything "
        f"before '@' and connect to the real host after it: '{parsed.hostname}'"
    )
    return _rule_result(
        "userinfo_present", triggered, reason,
        confidence=0.85, metadata={"hostname": parsed.hostname},
    )


def rule_brand_in_username(parsed):
    # Deliberately NOT run through find_typosquat_match (edit-distance):
    # a username is arbitrary attacker-controlled text, not a registered
    # domain, so typo-distance scoring doesn't apply - this looks for an
    # exact/near-exact real brand name instead.
    if not parsed.username:
        return _rule_result("brand_in_username", False, None)

    username_tokens = _tokenize(parsed.username)
    for popular in POPULAR_DOMAINS:
        popular_name = _matchable_brand_name(popular)
        if popular_name is None:
            continue
        if _token_matches(username_tokens, popular_name):
            reason = (
                f"Brand impersonation in username: '{parsed.username}' mimics "
                f"'{popular}', but the real destination is '{parsed.hostname}' - "
                f"likely a credential-stealing attempt"
            )
            return _rule_result(
                "brand_in_username", True, reason,
                confidence=0.95,
                metadata={"matched_brand": popular, "hostname": parsed.hostname},
            )
    return _rule_result("brand_in_username", False, None)


def rule_excessive_subdomains(parsed):
    triggered = parsed.subdomain.count(".") >= 2
    return _rule_result(
        "excessive_subdomains", triggered,
        "Excessive number of subdomains",
        confidence=0.5, metadata={"subdomain": parsed.subdomain},
    )


def _hostname_has_punycode_label(hostname):
    """True if any DNS label in hostname is Punycode/ACE-encoded (xn--).
    Shared by the hyphen and gibberish rules so both can avoid penalizing
    the encoding artifact itself (that's punycode_homograph's job)."""
    return any(label.lower().startswith("xn--") for label in (hostname or "").split(".") if label)


def _count_hyphens_excluding_ace_prefix(text):
    """Counts hyphens per-label, stripping a leading 'xn--' first. Every
    Punycode label starts with 'xn--', which contains a '--' that has
    nothing to do with attacker-chosen hyphenation - without stripping it,
    ANY internationalized domain (legitimate or not) would always trip
    excessive_hyphens just from the encoding prefix itself."""
    total = 0
    for label in text.split("."):
        if label.lower().startswith("xn--"):
            label = label[4:]
        total += label.count("-")
    return total


def rule_excessive_hyphens(parsed):
    combined = f"{parsed.subdomain}.{parsed.domain}" if parsed.subdomain else parsed.domain
    triggered = _count_hyphens_excluding_ace_prefix(combined) >= 2
    return _rule_result(
        "excessive_hyphens", triggered,
        "Excessive hyphens in domain/subdomain",
        confidence=0.5,
    )


def rule_gibberish_domain(parsed):
    # Skip entirely on Punycode-encoded labels: the raw ACE string
    # ("xn--80akhbyknj4f") is inherently a dense, near-random-looking
    # consonant run regardless of whether the underlying Unicode name is a
    # real word in another script (Cyrillic, Arabic, CJK, etc.) - the
    # consonant/vowel heuristic below is Latin-alphabet-specific and can't
    # fairly judge those scripts anyway. punycode_homograph already covers
    # the relevant signal for internationalized domains.
    if _hostname_has_punycode_label(parsed.hostname):
        return _rule_result("gibberish_domain", False, None, metadata={"skipped": "punycode_label"})

    triggered = looks_like_gibberish(parsed.domain)
    return _rule_result(
        "gibberish_domain", triggered,
        "Domain name looks randomly generated rather than a real word/brand",
        confidence=0.6,
    )


def rule_url_length(url):
    length = len(url)
    if length > 150:
        return _rule_result(
            "url_length", True,
            f"URL is unusually long ({length} characters) - often used to obscure the real destination",
            confidence=0.7, metadata={"length": length, "tier": "severe"},
        )
    if length > 100:
        return _rule_result(
            "url_length", True,
            f"URL is longer than typical ({length} characters)",
            confidence=0.4, metadata={"length": length, "tier": "moderate"},
        )
    return _rule_result("url_length", False, None, metadata={"length": length})


def rule_phishing_keywords_host(parsed):
    # Scans hostname + path + query (not scheme/userinfo - brand-in-username
    # above already covers userinfo more specifically).
    searchable_text = f"{parsed.hostname}{parsed.path}?{parsed.query}"
    decoded_text = unquote(searchable_text)
    tokens = _tokenize(decoded_text)
    hits = [kw for kw in PHISHING_KEYWORDS if _token_matches(tokens, kw)]

    if not hits:
        return _rule_result("phishing_keywords_host", False, None, metadata={"matched": []})

    # Confidence scales with how many distinct keyword hits were found,
    # capped at 0.9 - more hits is stronger evidence, but never treated
    # as absolutely certain on keywords alone.
    confidence = min(0.3 + 0.2 * len(hits), 0.9)
    shown = ", ".join(hits[:3])
    extra = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
    reason = f"Contains phishing-style keyword(s): {shown}{extra}"
    return _rule_result(
        "phishing_keywords_host", True, reason,
        confidence=confidence, metadata={"matched": hits},
    )


def rule_typosquatting(parsed):
    domain_words = _tokenize(parsed.domain)
    for word in domain_words:
        matched_brand = find_typosquat_match(word, parsed.suffix)
        if matched_brand:
            brand_name = matched_brand.split(".")[0]
            similarity = normalized_similarity(word, brand_name)
            reason = f"Domain looks suspiciously similar to '{matched_brand}' (possible typosquatting)"
            return _rule_result(
                "typosquatting", True, reason,
                # Confidence IS the normalized similarity score itself -
                # a domain 88% similar to a brand is treated as 88%
                # confident typosquatting, a natural, already-0-1 mapping.
                confidence=similarity,
                metadata={"matched_brand": matched_brand, "similarity": round(similarity, 3)},
            )
    return _rule_result("typosquatting", False, None)


def rule_brand_impersonation(parsed):
    if parsed.full_domain.lower() in KNOWN_INFRA_DOMAINS:
        lookup_text = parsed.subdomain.lower()
    else:
        lookup_text = f"{parsed.subdomain}.{parsed.domain}".lower()
    tokens = _tokenize(lookup_text)

    for popular in POPULAR_DOMAINS:
        popular_name = _matchable_brand_name(popular)
        if popular_name is None:
            continue
        if _token_matches(tokens, popular_name) and parsed.domain.lower() != popular_name:
            reason = f"Contains brand name '{popular_name}' but isn't the real site (possible impersonation)"
            return _rule_result(
                "brand_impersonation", True, reason,
                confidence=0.8, metadata={"matched_brand": popular_name},
            )
    return _rule_result("brand_impersonation", False, None)


def rule_domain_age(full_domain, verbose=False, network_info=None):
    if network_info is None:
        metadata = get_domain_age_metadata(full_domain, verbose=verbose)
    else:
        metadata = {"available": network_info.get("whois_available", False),
                    "age_days": network_info.get("age_days"), "note": None}
    age_days = metadata.get("age_days")
    if not metadata.get("available") or not isinstance(age_days, int):
        return _unavailable_rule_result("domain_age")

    if age_days < 30:
        reason = f"Domain registered only {age_days} days ago - very new domains are high risk"
        return _rule_result("domain_age", True, reason, confidence=0.9, metadata=metadata)
    if age_days < 180:
        reason = f"Domain registered {age_days} days ago - relatively new"
        return _rule_result("domain_age", True, reason, confidence=0.6, metadata=metadata)
    return _rule_result("domain_age", False, None, metadata=metadata)


_PATH_KEYWORD_CONFIDENCE = {"none": 0.0, "low": 0.4, "medium": 0.65, "high": 0.85}


def rule_path_keywords(parsed):
    # Delegates to the independent Part 4 path-analysis module (unchanged)
    # and simply maps its "none/low/medium/high" confidence label onto a
    # numeric 0.0-1.0 confidence for the scoring engine.
    result = analyze_path(parsed.path, parsed.query)
    triggered = bool(result["matched_keywords"])
    confidence = _PATH_KEYWORD_CONFIDENCE.get(result["confidence"], 0.0)
    return _rule_result(
        "path_keywords", triggered, result["reason"] if triggered else None,
        confidence=confidence, metadata={"matched_keywords": result["matched_keywords"]},
    )


_PUNYCODE_PRESENT_CONFIDENCE = {"none": 0.0, "low": 0.5, "high": 0.6}

# Minimum normalized similarity between a decoded Punycode label and a real
# brand name before we call it a confirmed homograph attack rather than just
# "this happens to be an internationalized domain." 0.8 comfortably catches
# single-confusable-character swaps (e.g. Cyrillic а for Latin a: "аpple" vs
# "apple" = 80% similarity) while still requiring the decoded name to be
# genuinely brand-shaped, not just superficially similar.
_PUNYCODE_BRAND_SIMILARITY_THRESHOLD = 0.8


def rule_punycode_present(parsed):
    """Weak, baseline signal: hostname contains a Punycode/ACE label at
    all. Being an internationalized domain is not inherently suspicious
    (most IDNs are legitimate), so this rule is deliberately low-weight -
    the real severity comes from rule_punycode_brand_homograph below.
    """
    result = analyze_punycode(parsed.hostname)
    triggered = result["score"] > 0
    confidence = _PUNYCODE_PRESENT_CONFIDENCE.get(result["confidence"], 0.0)
    return _rule_result(
        "punycode_present", triggered, result["reason"] if triggered else None,
        confidence=confidence, metadata={"decoded_domain": result["decoded_domain"]},
    )


def rule_punycode_brand_homograph(parsed):
    """Strong signal: the decoded Punycode label closely resembles a known
    brand name. This is what actually makes a Punycode domain a homograph
    ATTACK rather than just an internationalized domain - e.g. decoding
    'xn--pple-43d' to 'аpple' (Cyrillic а) and comparing it against the
    brand list catches the Apple-impersonation case on its own real merit,
    rather than via an unrelated/bogus token match elsewhere.
    """
    result = analyze_punycode(parsed.hostname)
    decoded_domain = result["decoded_domain"]
    if not decoded_domain:
        return _rule_result("punycode_brand_homograph", False, None)

    decoded_label = decoded_domain.split(".")[0].lower()
    for popular in POPULAR_DOMAINS:
        popular_name = _matchable_brand_name(popular)
        if popular_name is None:
            continue
        similarity = normalized_similarity(decoded_label, popular_name.lower())
        if similarity >= _PUNYCODE_BRAND_SIMILARITY_THRESHOLD:
            reason = (
                f"Punycode domain decodes to '{decoded_domain}', which closely matches "
                f"known brand '{popular_name}' (similarity {similarity:.0%}) - strong "
                f"indicator of a homograph brand-impersonation attack"
            )
            return _rule_result(
                "punycode_brand_homograph", True, reason,
                confidence=similarity,
                metadata={"matched_brand": popular_name, "similarity": round(similarity, 3), "decoded_domain": decoded_domain},
            )
    return _rule_result("punycode_brand_homograph", False, None)


# --- Scoring engine ------------------------------------------------------

def calculate_threat_score(rule_results, config=RULE_CONFIG):
    """Threat Score = sum(weight x confidence) over triggered rules,
    capped at 100. Purely arithmetic - no learned parameters.
    """
    total = 0.0
    for r in (_validate_rule_result(rule) for rule in rule_results):
        if r["triggered"]:
            weight = config.get(r["rule_id"], {}).get("weight", 0)
            total += weight * r["confidence"]
    return min(round(total), 100)


def calculate_risk_level(threat_score):
    """Fixed, human-auditable bands - easy to retune independently of
    rule weights if desired."""
    if threat_score >= 70:
        return "Critical"
    if threat_score >= 45:
        return "High"
    if threat_score >= 20:
        return "Medium"
    return "Low"


def calculate_overall_confidence(rule_results, config=RULE_CONFIG, data_completeness=1.0):
    """Overall Confidence (0-100%) - how sure the engine is in this
    specific verdict, distinct from the Threat Score itself.

    - No rules triggered: a flat baseline confidence in a "clean" verdict,
      scaled down slightly if some data source (e.g. WHOIS) was
      unavailable during this scan.
    - Rules triggered: the weight-weighted average of the confidences of
      the rules that fired, so heavily-weighted/high-certainty rules
      (e.g. brand_in_username at 0.95) dominate the average more than
      lightly-weighted/low-certainty ones (e.g. excessive_hyphens at 0.5),
      then scaled by the same data-completeness factor.
    """
    triggered = [_validate_rule_result(rule) for rule in rule_results if _validate_rule_result(rule)["triggered"]]

    if not triggered:
        baseline = 70.0
        return round(min(baseline * data_completeness, 100))

    weighted_sum = sum(
        config.get(r["rule_id"], {}).get("weight", 0) * r["confidence"] for r in triggered
    )
    weight_total = sum(
        config.get(r["rule_id"], {}).get("weight", 0) for r in triggered
    ) or 1
    avg_confidence = weighted_sum / weight_total  # 0.0-1.0
    return round(min(avg_confidence * 100 * data_completeness, 100))


_RECOMMENDATIONS = {
    "Low": "Safe to Visit",
    "Medium": "Proceed with Caution",
    "High": "Potential Phishing",
    "Critical": "Do NOT Visit",
}

_RECOMMENDATION_DETAILS = {
    "Low": "No significant phishing indicators were detected by the analysis engine.",
    "Medium": "Some suspicious indicators were detected. Verify the destination before continuing.",
    "High": "Multiple phishing indicators were detected. Avoid entering credentials or sensitive information.",
    "Critical": "A critical threat was detected. Do not open this URL or provide any information.",
}


def _build_response(raw_url, rule_results, threat_score, risk_level, confidence, data_completeness=1.0, domain_info=None):
    # 'flags' is kept as a flat list of human-readable reasons purely for
    # backward/template compatibility (existing Flask templates iterate
    # result['flags']); 'rules' carries the full structured detail for
    # anything more advanced (a rule-by-rule breakdown table, etc).
    rule_results = [_validate_rule_result(rule) for rule in (rule_results or [])]
    safe_domain_info = _validate_domain_info(domain_info)
    flags = [r["reason"] for r in rule_results if r["triggered"] and r["reason"]]

    # Final type guarantees on the documented contract - never None, never
    # the wrong type, regardless of what upstream computation produced.
    if risk_level not in _RECOMMENDATIONS:
        LOGGER.warning("Unexpected risk_level %r - defaulting to Medium", risk_level)
        risk_level = "Medium"
    try:
        threat_score = max(0, min(int(round(threat_score)), 100))
    except (TypeError, ValueError):
        LOGGER.warning("threat_score %r was not numeric - defaulting to 0", threat_score)
        threat_score = 0
    try:
        confidence = max(0, min(int(round(confidence)), 100))
    except (TypeError, ValueError):
        LOGGER.warning("confidence %r was not numeric - defaulting to 0", confidence)
        confidence = 0

    return {
        "url": raw_url if isinstance(raw_url, str) else "",
        "threat_score": threat_score,
        "score": threat_score,      # alias - Flask/template compatibility
        "risk_level": risk_level,
        "risk": risk_level,         # alias - Flask/template compatibility
        "confidence": confidence,
        "recommendation": _RECOMMENDATIONS[risk_level],
        "flags": flags,
        "rules": rule_results,
        "whois": {"available": bool(safe_domain_info.get("whois_available", False)),
                  "created_date": safe_domain_info.get("created_date", "Unavailable"),
                  "age_days": safe_domain_info.get("age_days", "Unavailable")},
        "domain_info": safe_domain_info,
        "metadata": {
            "data_completeness": data_completeness,
            "triggered_rule_count": len(flags),
            "recommendation_detail": _RECOMMENDATION_DETAILS[risk_level],
        },
    }


def _fallback_response(raw_url, reason):
    """Absolute last resort: used only if check_url()'s top-level safety
    net catches something unexpected that survived every other guard. Still
    satisfies the full documented contract (score/confidence/risk/flags/
    recommendation/whois/domain_info all present, correctly typed) so a
    caller (Flask, the template, the database layer) never has to
    special-case "the detector didn't return the shape I expected."
    """
    LOGGER.error("check_url() hit its top-level safety net for url=%r: %s", raw_url, reason)
    return _build_response(
        raw_url if isinstance(raw_url, str) else "",
        [_rule_result("scan_error", True, f"Scan could not complete: {reason}", confidence=1.0, metadata={})],
        threat_score=50,
        risk_level="Medium",
        confidence=0,
        data_completeness=0.0,
        domain_info=None,
    )


def check_url(raw_url):
    """Main entry point. Runs every rule, then hands the collected
    RuleResults to the scoring engine (calculate_threat_score /
    calculate_risk_level / calculate_overall_confidence) to produce the
    final Threat Score (0-100), Risk Level, and Overall Confidence (0-100%).

    Guarantees (see requirements from the Issue 1/Issue 2 audit): this
    function can never raise. Every module it calls is validated at the
    boundary before its output is used (_validate_domain_info for
    get_domain_information(), _validate_rule_result for every rule), and
    this outer try/except is the last-resort safety net if something
    unforeseen still slips through - the detector must never crash a scan
    because one module failed.
    """
    try:
        if not isinstance(raw_url, str) or not raw_url.strip():
            return _fallback_response(raw_url, "empty or non-string URL")

        url = raw_url.strip()

        # 0a/0b. Scheme validation happens before anything else - an invalid
        # scheme (javascript:, data:, ftp:, etc.) is an automatic Critical
        # verdict (weight 100, confidence 1.0 => threat score 100), since
        # parsing domain structure on a non-http(s) URI isn't meaningful.
        scheme_match = _SCHEME_PATTERN.match(url)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            if scheme not in ("http", "https"):
                rule_results = [rule_disallowed_scheme(scheme)]
                threat_score = calculate_threat_score(rule_results)
                risk_level = calculate_risk_level(threat_score)
                confidence = calculate_overall_confidence(rule_results, data_completeness=1.0)
                return _build_response(raw_url, rule_results, threat_score, risk_level, confidence)
            # Valid scheme, normalize its case so downstream checks are reliable.
            url = scheme + url[scheme_match.end(1):]
        else:
            # No scheme at all (e.g. "example.com") - assume http, as before.
            url = "http://" + url

        # Parse once - every rule below reads from this single representation.
        parsed = _parse_url_components(url)

        # Phase 1: deterministic rules do not require network access.
        fast_rule_results = [
            _rule_result("disallowed_scheme", False, None),
            rule_malformed_whitespace(url),
            rule_no_https(parsed),
            rule_ip_address_host(parsed),
            rule_suspicious_tld(parsed),
            rule_url_shortener(parsed),
            rule_userinfo_present(parsed),
            rule_brand_in_username(parsed),
            rule_excessive_subdomains(parsed),
            rule_excessive_hyphens(parsed),
            rule_gibberish_domain(parsed),
            rule_url_length(url),
            rule_phishing_keywords_host(parsed),
            rule_typosquatting(parsed),
            rule_brand_impersonation(parsed),
            rule_path_keywords(parsed),
            rule_punycode_present(parsed),
            rule_punycode_brand_homograph(parsed),
        ]

        # Phase 2: bounded concurrent WHOIS, DNS/hosting and TLS enrichment.
        # get_domain_information() is itself defensively written to never
        # raise and never return None fields - but it's an external module
        # boundary, so we validate its output here regardless of how
        # trustworthy it claims to be. This is the fix for the audited gap:
        # nothing previously checked this dict's shape/types before a rule
        # function used it in a numeric comparison.
        try:
            raw_domain_info = get_domain_information(url)
        except Exception as error:
            LOGGER.exception("get_domain_information() raised for url=%r: %s", url, error)
            raw_domain_info = None
        domain_info = _validate_domain_info(raw_domain_info)

        # Phase 3: merge the resulting age rule into the completed fast results.
        domain_age_result = rule_domain_age(parsed.full_domain, verbose=VERBOSE, network_info=domain_info)
        whois_available = domain_age_result["metadata"].get("available", False)
        data_completeness = 1.0 if whois_available else 0.9
        rule_results = fast_rule_results + [domain_age_result]

        threat_score = calculate_threat_score(rule_results)
        risk_level = calculate_risk_level(threat_score)
        confidence = calculate_overall_confidence(rule_results, data_completeness=data_completeness)

        return _build_response(raw_url, rule_results, threat_score, risk_level, confidence, data_completeness, domain_info)

    except Exception as error:
        # Last-resort safety net. Every module above is already individually
        # hardened, so reaching this point means something truly unforeseen
        # happened - but the detector still must not crash the caller.
        LOGGER.exception("check_url() failed unexpectedly for url=%r: %s", raw_url, error)
        return _fallback_response(raw_url, str(error))


if __name__ == "__main__":
    # Test URLs are grouped and explicitly labeled as PHISHING or LEGITIMATE
    # (ground truth, not detector output), so the printed report shows
    # whether the new weighted engine's verdict matches reality.
    test_urls = [
        # --- Legitimate ------------------------------------------------
        ("https://www.google.com", "legitimate"),
        ("https://www.reddit.com", "legitimate"),
        ("https://www.cataloginfo.com/products", "legitimate"),
        ("https://example.com/promo.click", "legitimate"),
        ("https://www.microsoft.com/account/password/reset?confirm=true", "legitimate"),
        ("https://xn--80akhbyknj4f.xn--p1ai/", "legitimate"),

        # --- Phishing / malicious ---------------------------------------
        ("http://192.168.1.1/login", "phishing"),
        ("http://paypa1-secure-login.xyz/account", "phishing"),
        ("https://bit.ly/3xample", "phishing"),
        ("http://www.faceb00k.com@evil.com/login", "phishing"),
        ("googgle.com.in", "phishing"),
        ("sslkislksd.com", "phishing"),
        ("https://allegrolokalnie.lato-2026-523924.click", "phishing"),
        ("https://sparkase-hamm.de/", "phishing"),
        ("https://itauclientes-nqxep046f-gamero-galons-projects.vercel.app/", "phishing"),
        ("http://sbi-verify-account.xyz/login/confirm-details", "phishing"),
        ("javascript:alert(document.cookie)", "phishing"),
        ("https://free-gift-cards.com/webscr/verify/secure-login", "phishing"),
        ("https://tracking-delivery-status.com/account/update/password", "phishing"),
        ("https://xn--pple-43d.com/signin", "phishing"),
    ]

    for u, label in test_urls:
        result = check_url(u)
        predicted_phishing = result["risk_level"] != "Low"
        match = "✓" if predicted_phishing == (label == "phishing") else "✗"
        print("=" * 70)
        print(f"URL:         {result['url']}")
        print(f"Label:       {label.upper()}")
        print(f"Threat:      {result['threat_score']}/100   Risk: {result['risk_level']}   "
              f"Confidence: {result['confidence']}%   [{match}]")
        triggered_rules = [r for r in result["rules"] if r["triggered"]]
        if not triggered_rules:
            print("  - (no rules triggered)")
        for r in triggered_rules:
            weight = RULE_CONFIG.get(r["rule_id"], {}).get("weight", 0)
            points = round(weight * r["confidence"], 1)
            print(f"  - [{r['rule_id']}] {r['reason']}  "
                  f"(weight={weight}, confidence={r['confidence']}, points={points})")

    print("=" * 70)