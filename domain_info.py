"""Concurrent, failure-safe domain enrichment for URL scans.

Fixes applied after root-cause audit (see conversation / CHANGELOG):

  BUG FIXED - _record_fields() used to return a bare positional tuple, and
  its "record is None" branch returned 6 values while every caller unpacked
  7 - a guaranteed ValueError whenever WHOIS didn't come back in time
  (which, given WHOIS's real-world latency, was effectively always). That
  crash was caught by a blanket except, which silently discarded EVERY
  already-gathered field (including DNS/SSL, which had often already
  succeeded) and replaced the whole result with "Unavailable". _record_fields
  now returns a dict, not a tuple - a missing/extra field is structurally
  impossible to mis-unpack.

  TIMEOUT FIXED - WHOIS previously shared the same 2-second budget as DNS
  and SSL. DNS/SSL are fast single-round-trip operations that comfortably
  finish in under 2s; WHOIS requires an IANA-then-registrar referral chain
  that the underlying `whois` library does NOT reliably bound even via its
  own `timeout` kwarg (confirmed in this project's own historical comments).
  WHOIS now gets its own, longer, dedicated timeout.

  VALIDATION ADDED - every return path now goes through _validate_result(),
  which guarantees every documented key is present with a safe type/value
  before the dict leaves this module. No field is ever raw None.

  TIMEZONE BUG FIXED (found via WHOIS_DEBUG logs) - age_days was computed as
  `datetime.now() - created`, i.e. a naive datetime minus whatever WHOIS
  returned for creation_date. Real registries (verified against both
  google.com and a live phishing sample) return creation_date as tz-aware
  (`tzinfo=tzoffset('UTC', 0)`), so this raised
  `TypeError("can't subtract offset-naive and offset-aware datetimes")` for
  EVERY domain - legitimate or malicious - not just slow/unresponsive ones.
  That TypeError was swallowed by _record_fields()'s own except block, which
  then discarded the entire already-parsed WHOIS dict (registrar, dates,
  country) and reported it all as "Unavailable", even though parsing had
  succeeded right up until that line. The expiry-side calculation a few
  lines below already branched on `expiry.tzinfo` correctly - the same fix
  just hadn't been applied to age_days. Both now go through a single
  `_now_for()` helper so the two code paths can't drift out of sync again.
"""

import logging
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
from urllib.parse import urlsplit

import tldextract
import whois

LOGGER = logging.getLogger(__name__)

# Set to True to see step-by-step WHOIS debug prints (original URL,
# extracted hostname, registrable domain, WHOIS target, raw WHOIS response,
# and each parsed field) as requested during this investigation. Safe to
# leave on in development; turn off for a quiet production log.
WHOIS_DEBUG = True

UNAVAILABLE = "Unavailable"
NOT_APPLICABLE = "Not Applicable"

# DNS and SSL are fast, single-round-trip operations - 2s is generous.
DNS_SSL_TIMEOUT_SECONDS = 2

# WHOIS needs its own, much more forgiving budget: real-world WHOIS lookups
# frequently involve an IANA referral (~1-2s) followed by the registrar's
# own WHOIS server (another 1-4s), and some registrars are simply slow.
# This is a HARD wall-clock cap via a Future timeout, not a hint - if it's
# exceeded, we cleanly report "Unavailable" rather than blocking forever.
WHOIS_TIMEOUT_SECONDS = 6

CACHE_TTL_SECONDS = 30 * 60
FAILED_WHOIS_CACHE_TTL_SECONDS = 60

_extract = tldextract.TLDExtract(suffix_list_urls=())
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="domain-info")
_cache, _whois_success_cache, _whois_failure_cache, _cache_lock = {}, {}, {}, threading.Lock()
_COUNTRIES = {"US": "United States", "IN": "India", "GB": "United Kingdom", "UK": "United Kingdom", "CA": "Canada", "AU": "Australia", "DE": "Germany", "FR": "France", "JP": "Japan"}

# The complete, documented set of fields get_domain_information() promises.
# _validate_result() guarantees every one of these is present with a safe
# type on every single return path - this is what makes "never return an
# incomplete/None-bearing object" a structural guarantee rather than a
# per-branch convention that's easy to accidentally break (as happened with
# the tuple-arity bug this replaces).
_FIELD_DEFAULTS = {
    "hostname": UNAVAILABLE,
    "registrable_domain": UNAVAILABLE,
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
    "age_days": UNAVAILABLE,
    "domain_age": UNAVAILABLE,
    "expires_in": UNAVAILABLE,
}


def _validate_result(result):
    """Guarantees a complete, safely-typed dict with every documented key.
    Called at the end of every code path in this module - regardless of how
    a result was built, it passes through here before being returned, so a
    missing key or a raw None can never leak out to a caller.
    """
    if not isinstance(result, dict):
        LOGGER.warning("domain_info produced a non-dict result (%r) - substituting safe defaults", type(result))
        result = {}
    safe = dict(_FIELD_DEFAULTS)
    for key, default in _FIELD_DEFAULTS.items():
        value = result.get(key, default)
        if value is None:
            LOGGER.warning("domain_info field '%s' was None - substituting default %r", key, default)
            value = default
        if key == "whois_available":
            value = bool(value)
        safe[key] = value
    return safe


def _cache_get(key):
    with _cache_lock:
        value = _cache.get(key)
        if value and time.monotonic() - value[1] < CACHE_TTL_SECONDS:
            return value[0]
    return None


def _cache_set(key, value):
    with _cache_lock:
        _cache[key] = (value, time.monotonic())


def _whois_cache_get(cache, domain, ttl):
    with _cache_lock:
        entry = cache.get(domain)
        return entry[0] if entry and time.monotonic() - entry[1] < ttl else None


def _whois_cache_set(cache, domain, value):
    with _cache_lock:
        cache[domain] = (value, time.monotonic())


def _unavailable():
    return _validate_result({})


def _not_applicable():
    result = dict(_FIELD_DEFAULTS)
    for key in result:
        if key not in ("whois_available", "age_days"):
            result[key] = NOT_APPLICABLE
    return _validate_result(result)


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _now_for(reference):
    """Return a `datetime.now()` comparable to `reference`.

    WHOIS libraries return naive datetimes for some registries and
    tz-aware datetimes for others (confirmed for both google.com and a
    live phishing sample in this project's own debug logs), so we match
    tz-awareness explicitly instead of assuming either representation.
    This is the single source of truth for "now" in this module - both
    age_days and expires_in go through it so they can't drift apart again.
    """
    tzinfo = getattr(reference, "tzinfo", None)
    return datetime.now(tzinfo) if tzinfo else datetime.now()


def _format_date(value, missing="Unknown"):
    value = _first(value)
    return value.strftime("%d/%m/%Y") if hasattr(value, "strftime") else missing


def _normalize_registrar(value):
    value = str(_first(value) or "").strip().rstrip(".,")
    canonical = {"google llc": "Google LLC", "markmonitor inc": "MarkMonitor Inc."}
    return canonical.get(value.lower(), value.title() if value else "Unknown")


def _normalize_country(value):
    value = str(_first(value) or "").strip()
    return _COUNTRIES.get(value.upper(), value.title() if value else "Unknown")


def _relative_time(days, future=False):
    if not isinstance(days, int):
        return "Unknown"
    years, remaining = divmod(abs(days), 365)
    if years:
        text = f"{years} year{'s' if years != 1 else ''}"
    else:
        text = f"{max(remaining, 0)} day{'s' if remaining != 1 else ''}"
    return f"Expires in {text}" if future else text


def _whois_lookup(domain):
    """Runs in the thread pool. Always returns a record object or None -
    never raises (every failure mode is caught and cached as a negative
    result so we don't hammer a slow/dead WHOIS server on every request).
    """
    cached = _whois_cache_get(_whois_success_cache, domain, CACHE_TTL_SECONDS)
    if cached is not None:
        if WHOIS_DEBUG:
            print(f"[whois-debug] cache hit (success) for {domain}")
        return cached
    if _whois_cache_get(_whois_failure_cache, domain, FAILED_WHOIS_CACHE_TTL_SECONDS) is not None:
        if WHOIS_DEBUG:
            print(f"[whois-debug] cache hit (recent failure) for {domain} - skipping network call")
        return None

    if WHOIS_DEBUG:
        print(f"[whois-debug] WHOIS lookup target: {domain}")
    try:
        result = whois.whois(domain, timeout=WHOIS_TIMEOUT_SECONDS)
        if WHOIS_DEBUG:
            print(f"[whois-debug] Raw WHOIS response for {domain}: {result!r}")
        if result is None:
            raise RuntimeError("WHOIS returned no record")
        _whois_cache_set(_whois_success_cache, domain, result)
        return result
    except Exception as error:
        if WHOIS_DEBUG:
            print(f"[whois-debug] WHOIS lookup FAILED for {domain}: {error!r}")
        LOGGER.info("WHOIS unavailable for %s: %s", domain, error)
        _whois_cache_set(_whois_failure_cache, domain, True)
        return None


def _dns_and_hosting(hostname):
    key = ("dns_hosting", hostname)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    ip, hosting = UNAVAILABLE, UNAVAILABLE
    try:
        ip = socket.gethostbyname(hostname)
        try:
            hosting = socket.gethostbyaddr(ip)[0] or UNAVAILABLE
        except Exception as error:
            LOGGER.info("Hosting lookup unavailable for %s: %s", hostname, error)
    except Exception as error:
        LOGGER.info("DNS unavailable for %s: %s", hostname, error)
    result = (ip, hosting)
    _cache_set(key, result)
    return result


def _ssl_status(hostname):
    key = ("ssl", hostname)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=DNS_SSL_TIMEOUT_SECONDS) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls:
                result = "Valid (TLS)" if tls.getpeercert() else "Present (unverified)"
    except ssl.SSLError as error:
        LOGGER.info("SSL validation unavailable for %s: %s", hostname, error)
        result = "Invalid/Expired"
    except Exception as error:
        LOGGER.info("SSL unavailable for %s: %s", hostname, error)
        result = UNAVAILABLE
    _cache_set(key, result)
    return result


def _record_fields(record):
    """Returns a DICT (never a positional tuple - that's exactly the bug
    class that caused the arity mismatch this replaces) with keys:
    registrar, created_date, expiry_date, country, age_days, domain_age,
    expires_in, whois_available. Every branch returns every key - there is
    no way for a caller to receive fewer fields than expected.
    """
    if WHOIS_DEBUG:
        print(f"[whois-debug] Parsing WHOIS record: {record!r}")

    if record is None:
        if WHOIS_DEBUG:
            print("[whois-debug] Parsed registrar: Unavailable (no record)")
            print("[whois-debug] Parsed creation date: Unavailable (no record)")
            print("[whois-debug] Parsed expiration date: Unavailable (no record)")
            print("[whois-debug] Parsed country: Unavailable (no record)")
        return {
            "registrar": UNAVAILABLE, "created_date": UNAVAILABLE, "expiry_date": UNAVAILABLE,
            "country": UNAVAILABLE, "age_days": UNAVAILABLE, "domain_age": UNAVAILABLE,
            "expires_in": UNAVAILABLE, "whois_available": False,
        }

    try:
        created = _first(getattr(record, "creation_date", None))
        expiry = _first(getattr(record, "expiration_date", None))
        raw_registrar = getattr(record, "registrar", None)
        raw_country = getattr(record, "country", None)

        age_days = max((_now_for(created) - created).days, 0) if hasattr(created, "year") else UNAVAILABLE

        if hasattr(expiry, "year"):
            expiry_days = (expiry - _now_for(expiry)).days
            expires_in = _relative_time(expiry_days, future=True) if expiry_days >= 0 else f"Expired {abs(expiry_days)} days ago"
        else:
            expires_in = "Unknown"

        registrar = _normalize_registrar(raw_registrar)
        created_date = _format_date(created)
        expiry_date = _format_date(expiry)
        country = _normalize_country(raw_country)
        domain_age = _relative_time(age_days) if isinstance(age_days, int) else "Unknown"

        if WHOIS_DEBUG:
            print(f"[whois-debug] Parsed registrar: {registrar}")
            print(f"[whois-debug] Parsed creation date: {created_date} (raw={created!r})")
            print(f"[whois-debug] Parsed expiration date: {expiry_date} (raw={expiry!r})")
            print(f"[whois-debug] Parsed country: {country}")

        return {
            "registrar": registrar, "created_date": created_date, "expiry_date": expiry_date,
            "country": country, "age_days": age_days, "domain_age": domain_age,
            "expires_in": expires_in, "whois_available": True,
        }
    except Exception as error:
        if WHOIS_DEBUG:
            print(f"[whois-debug] Malformed WHOIS result while parsing {record!r}: {error!r}")
        LOGGER.info("Malformed WHOIS result: %s", error)
        return {
            "registrar": UNAVAILABLE, "created_date": UNAVAILABLE, "expiry_date": UNAVAILABLE,
            "country": UNAVAILABLE, "age_days": UNAVAILABLE, "domain_age": UNAVAILABLE,
            "expires_in": UNAVAILABLE, "whois_available": False,
        }


def get_domain_information(url):
    """Return fast parsed fields plus concurrent, bounded network enrichment.

    DNS and SSL are bounded by DNS_SSL_TIMEOUT_SECONDS; WHOIS is bounded
    separately (and more generously) by WHOIS_TIMEOUT_SECONDS, since it
    structurally needs longer. Every return path - success, partial
    failure, or total failure - passes through _validate_result() before
    reaching the caller, so the returned dict is always complete and never
    contains a raw None.
    """
    try:
        raw = (url or "").strip()
        if WHOIS_DEBUG:
            print(f"[whois-debug] Original URL: {raw}")
        LOGGER.info("Domain info URL=%s", raw)

        split = urlsplit(raw)
        if split.scheme and split.scheme not in ("http", "https"):
            return _not_applicable()
        if not split.scheme:
            split = urlsplit("http://" + raw)
        hostname = (split.hostname or "").lower()
        if WHOIS_DEBUG:
            print(f"[whois-debug] Extracted hostname: {hostname or '(none)'}")
        if not hostname:
            return _unavailable()

        parts = _extract(hostname)
        full_domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
        if WHOIS_DEBUG:
            print(f"[whois-debug] Registrable domain: {full_domain or '(none)'}")
            print(f"[whois-debug] WHOIS lookup target: {full_domain or '(none)'}")
        LOGGER.info("Domain info hostname=%s registrable_domain=%s", hostname, full_domain)

        base = {
            "hostname": hostname,
            "registrable_domain": full_domain or UNAVAILABLE,
            "domain": full_domain or UNAVAILABLE,
            "subdomain": parts.subdomain or UNAVAILABLE,
            "suffix": parts.suffix or UNAVAILABLE,
        }
        if not full_domain:
            return _validate_result(base)

        # WHOIS gets its own, longer-running future - we wait for DNS/SSL
        # on the fast, tight budget, then separately give WHOIS its own
        # realistic budget rather than sharing (and being starved by) the
        # same short window.
        whois_future = _executor.submit(_whois_lookup, full_domain)
        dns_future = _executor.submit(_dns_and_hosting, hostname)
        ssl_future = _executor.submit(_ssl_status, hostname)

        fast_done, _ = wait([dns_future, ssl_future], timeout=DNS_SSL_TIMEOUT_SECONDS)
        whois_done, _ = wait([whois_future], timeout=WHOIS_TIMEOUT_SECONDS)

        def _safe_result(future, default, done_set):
            if future not in done_set:
                return default
            try:
                return future.result()
            except Exception as error:
                LOGGER.info("Lookup failed: %s", error)
                return default

        whois_record = _safe_result(whois_future, None, whois_done)
        ip_address, hosting_provider = _safe_result(dns_future, (UNAVAILABLE, UNAVAILABLE), fast_done)
        ssl_status = _safe_result(ssl_future, UNAVAILABLE, fast_done)

        whois_fields = _record_fields(whois_record)

        result = dict(base)
        result.update(whois_fields)
        result["ip_address"] = ip_address
        result["hosting_provider"] = hosting_provider
        result["ssl_status"] = ssl_status
        return _validate_result(result)

    except Exception as error:
        LOGGER.exception("Domain enrichment failed: %s", error)
        return _unavailable()