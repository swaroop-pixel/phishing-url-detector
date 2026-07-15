"""Domain metadata collection module.

Completely independent from detector.py: this module never touches, imports
from, or influences the phishing risk-scoring logic. Its only job is to
gather human-readable "Domain Information" panel data (registrar, dates,
IP, hosting, SSL, etc.) and hand back a dict of strings.

Design contract:
  - get_domain_information(url) NEVER raises.
  - Every field is independently fault-tolerant: a WHOIS outage cannot blank
    out DNS/SSL fields and vice versa.
  - Any field that can't be determined is returned as the literal string
    "Unavailable" - never None, never an exception, never a partial object -
    so the Flask template can render it directly.
  - All network calls (WHOIS, DNS, reverse DNS, SSL handshake) are wrapped
    with a hard timeout via a thread pool, since several of these calls
    (socket.gethostbyname, whois.whois's IANA referral step) have no
    reliable timeout parameter of their own and can otherwise hang.
  - Lightweight in-memory TTL caches avoid re-querying WHOIS/DNS for the
    same host on every repeated scan.
"""

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from urllib.parse import urlsplit

import tldextract
import whois

UNAVAILABLE = "Unavailable"

# Use the bundled snapshot instead of fetching the public suffix list over
# the network on every call (mirrors detector.py's approach).
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

_WHOIS_TIMEOUT_SECONDS = 3
_DNS_TIMEOUT_SECONDS = 3
_SSL_TIMEOUT_SECONDS = 3

_CACHE_TTL_SECONDS = 3600

_whois_executor = ThreadPoolExecutor(max_workers=4)
_dns_executor = ThreadPoolExecutor(max_workers=4)

_whois_cache = {}
_ip_cache = {}
_hosting_cache = {}


def _cache_get(cache, key):
    entry = cache.get(key)
    if entry is None:
        return None, False
    value, cached_at = entry
    if time.time() - cached_at < _CACHE_TTL_SECONDS:
        return value, True
    return None, False


def _cache_set(cache, key, value):
    cache[key] = (value, time.time())


def _hostname_from_url(url):
    """Extracts a bare lowercase hostname from a URL that may or may not
    already have a scheme. Never raises - returns "" on anything unparsable.
    """
    try:
        candidate = (url or "").strip()
        if "://" not in candidate:
            candidate = "http://" + candidate
        return (urlsplit(candidate).hostname or "").lower()
    except Exception:
        return ""


def _first(value):
    """WHOIS fields are sometimes a list (e.g. multiple creation_date
    entries from a messy registrar record) and sometimes a scalar."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _format_date(value):
    value = _first(value)
    if value is None:
        return UNAVAILABLE
    try:
        return value.strftime("%Y-%m-%d")
    except AttributeError:
        return str(value) if value else UNAVAILABLE


def _safe_field(value):
    value = _first(value)
    return value if value else UNAVAILABLE


# --- WHOIS -------------------------------------------------------------

def _whois_lookup(full_domain):
    return whois.whois(full_domain, timeout=_WHOIS_TIMEOUT_SECONDS)


def _get_whois_record(full_domain):
    """Returns a whois record object, or None on any failure. Never raises,
    never prints. Cached per domain."""
    if not full_domain:
        return None

    cached, hit = _cache_get(_whois_cache, full_domain)
    if hit:
        return cached

    record = None
    try:
        future = _whois_executor.submit(_whois_lookup, full_domain)
        record = future.result(timeout=_WHOIS_TIMEOUT_SECONDS)
    except FutureTimeoutError:
        record = None
    except Exception:
        record = None

    _cache_set(_whois_cache, full_domain, record)
    return record


# --- DNS / IP ------------------------------------------------------------

def _resolve_ip(hostname):
    """Resolves hostname -> IPv4 string, or None on failure. Hard-timeout
    via thread pool since socket.gethostbyname has no timeout param."""
    if not hostname:
        return None

    cached, hit = _cache_get(_ip_cache, hostname)
    if hit:
        return cached

    ip = None
    try:
        future = _dns_executor.submit(socket.gethostbyname, hostname)
        ip = future.result(timeout=_DNS_TIMEOUT_SECONDS)
    except FutureTimeoutError:
        ip = None
    except Exception:
        ip = None

    _cache_set(_ip_cache, hostname, ip)
    return ip


def _resolve_hosting_provider(ip):
    """Best-effort reverse DNS (PTR) lookup on the resolved IP, used as a
    proxy for 'who hosts this' (e.g. reveals AWS/Google/Cloudflare PTR
    patterns) since no external IP-WHOIS/ASN service is in scope here.
    Returns "Unavailable" on any failure - never raises.
    """
    if not ip:
        return UNAVAILABLE

    cached, hit = _cache_get(_hosting_cache, ip)
    if hit:
        return cached

    provider = UNAVAILABLE
    try:
        future = _dns_executor.submit(socket.gethostbyaddr, ip)
        ptr_hostname, _aliases, _addrs = future.result(timeout=_DNS_TIMEOUT_SECONDS)
        provider = ptr_hostname or UNAVAILABLE
    except FutureTimeoutError:
        provider = UNAVAILABLE
    except Exception:
        provider = UNAVAILABLE

    _cache_set(_hosting_cache, ip, provider)
    return provider


# --- SSL -------------------------------------------------------------------

def _check_ssl(hostname):
    """Attempts a real TLS handshake on port 443. Returns one of:
    "Valid (TLS)", "Invalid/Expired", or "Unavailable" (unreachable, no
    HTTPS, timeout, or any other failure). Never raises.
    """
    if not hostname:
        return UNAVAILABLE

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=_SSL_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                return "Valid (TLS)" if cert else "Present (unverified)"
    except ssl.SSLCertVerificationError:
        return "Invalid/Expired"
    except ssl.SSLError:
        return "Invalid/Expired"
    except Exception:
        # Connection refused, timeout, no route, DNS failure, etc. - all
        # collapse to "Unavailable" rather than raising.
        return UNAVAILABLE


# --- Public entry point ------------------------------------------------

def get_domain_information(url):
    """Collects Domain Information panel metadata for `url`.

    Never raises. Every field independently degrades to "Unavailable" on
    failure. Safe to call unconditionally alongside check_url() - a WHOIS
    or DNS outage here can never affect or interrupt phishing detection.
    """
    try:
        hostname = _hostname_from_url(url)
        extracted = _tld_extractor(hostname)

        domain = extracted.domain or UNAVAILABLE
        subdomain = extracted.subdomain or UNAVAILABLE
        suffix = extracted.suffix or UNAVAILABLE
        full_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        record = _get_whois_record(full_domain)
        whois_available = record is not None

        registrar = UNAVAILABLE
        created_date = UNAVAILABLE
        expiry_date = UNAVAILABLE
        country = UNAVAILABLE

        if record is not None:
            # Each field read independently - a missing/odd attribute on
            # one field must not block the others.
            try:
                registrar = _safe_field(getattr(record, "registrar", None))
            except Exception:
                pass
            try:
                created_date = _format_date(getattr(record, "creation_date", None))
            except Exception:
                pass
            try:
                expiry_date = _format_date(getattr(record, "expiration_date", None))
            except Exception:
                pass
            try:
                country = _safe_field(getattr(record, "country", None))
            except Exception:
                pass

        ip_address = _resolve_ip(hostname) or UNAVAILABLE
        hosting_provider = _resolve_hosting_provider(ip_address if ip_address != UNAVAILABLE else None)
        ssl_status = _check_ssl(hostname)

        return {
            "domain": domain,
            "subdomain": subdomain,
            "suffix": suffix,
            "registrar": registrar,
            "created_date": created_date,
            "expiry_date": expiry_date,
            "country": country,
            "ip_address": ip_address,
            "hosting_provider": hosting_provider,
            "ssl_status": ssl_status,
            "whois_available": whois_available,
        }
    except Exception:
        # Absolute last resort - should be unreachable given the try/except
        # coverage above, but guarantees this function truly never raises.
        return {
            "domain": UNAVAILABLE,
            "subdomain": UNAVAILABLE,
            "suffix": UNAVAILABLE,
            "registrar": UNAVAILABLE,
            "created_date": UNAVAILABLE,
            "expiry_date": UNAVAILABLE,
            "country": UNAVAILABLE,
            "ip_address": UNAVAILABLE,
            "hosting_provider": UNAVAILABLE,
            "ssl_status": UNAVAILABLE,
            "whois_available": False,
        }
