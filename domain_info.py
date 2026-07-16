"""Concurrent, failure-safe domain enrichment for URL scans."""

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
UNAVAILABLE = "Unavailable"
NOT_APPLICABLE = "Not Applicable"
NETWORK_TIMEOUT_SECONDS = 2
CACHE_TTL_SECONDS = 30 * 60

_extract = tldextract.TLDExtract(suffix_list_urls=())
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="domain-info")
_cache, _cache_lock = {}, threading.Lock()


def _cache_get(key):
    with _cache_lock:
        value = _cache.get(key)
        if value and time.monotonic() - value[1] < CACHE_TTL_SECONDS:
            return value[0]
    return None


def _cache_set(key, value):
    with _cache_lock:
        _cache[key] = (value, time.monotonic())


def _unavailable():
    return {"domain": UNAVAILABLE, "subdomain": UNAVAILABLE, "suffix": UNAVAILABLE,
            "registrar": UNAVAILABLE, "created_date": UNAVAILABLE, "expiry_date": UNAVAILABLE,
            "country": UNAVAILABLE, "ip_address": UNAVAILABLE, "hosting_provider": UNAVAILABLE,
            "ssl_status": UNAVAILABLE, "whois_available": False, "age_days": None}


def _not_applicable():
    result = _unavailable()
    for key in result:
        if key not in ("whois_available", "age_days"):
            result[key] = NOT_APPLICABLE
    return result


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _format_date(value):
    value = _first(value)
    return value.strftime("%Y-%m-%d") if hasattr(value, "strftime") else (str(value) if value else UNAVAILABLE)


def _whois(domain):
    key = ("whois", domain)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        result = whois.whois(domain, timeout=NETWORK_TIMEOUT_SECONDS)
    except Exception as error:
        LOGGER.info("WHOIS unavailable for %s: %s", domain, error)
        result = None
    _cache_set(key, result)
    return result


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
        with socket.create_connection((hostname, 443), timeout=NETWORK_TIMEOUT_SECONDS) as connection:
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
    if record is None:
        return UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, None
    try:
        created = _first(getattr(record, "creation_date", None))
        age_days = max((datetime.now() - created).days, 0) if hasattr(created, "year") else None
        return (_first(getattr(record, "registrar", None)) or UNAVAILABLE,
                _format_date(created), _format_date(getattr(record, "expiration_date", None)),
                _first(getattr(record, "country", None)) or UNAVAILABLE, age_days)
    except Exception as error:
        LOGGER.info("Malformed WHOIS result: %s", error)
        return UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, None


def get_domain_information(url):
    """Return fast parsed fields plus concurrent, bounded network enrichment.

    The caller returns after two seconds even when a provider thread is still
    stuck; incomplete fields are represented as ``Unavailable``.
    """
    try:
        raw = (url or "").strip()
        split = urlsplit(raw)
        if split.scheme and split.scheme not in ("http", "https"):
            return _not_applicable()
        if not split.scheme:
            split = urlsplit("http://" + raw)
        hostname = (split.hostname or "").lower()
        if not hostname:
            return _unavailable()
        parts = _extract(hostname)
        full_domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
        result = _unavailable()
        result.update({"domain": parts.domain or UNAVAILABLE, "subdomain": parts.subdomain or UNAVAILABLE,
                       "suffix": parts.suffix or UNAVAILABLE})
        if not full_domain:
            return result

        futures = {"whois": _executor.submit(_whois, full_domain),
                   "dns": _executor.submit(_dns_and_hosting, hostname),
                   "ssl": _executor.submit(_ssl_status, hostname)}
        done, _ = wait(futures.values(), timeout=NETWORK_TIMEOUT_SECONDS)
        values = {}
        for name, future in futures.items():
            if future in done:
                try:
                    values[name] = future.result()
                except Exception as error:
                    LOGGER.info("%s lookup failed: %s", name, error)
        registrar, created, expiry, country, age_days = _record_fields(values.get("whois"))
        result.update({"registrar": registrar, "created_date": created, "expiry_date": expiry,
                       "country": country, "age_days": age_days,
                       "whois_available": values.get("whois") is not None,
                       "ssl_status": values.get("ssl", UNAVAILABLE)})
        result["ip_address"], result["hosting_provider"] = values.get("dns", (UNAVAILABLE, UNAVAILABLE))
        return result
    except Exception as error:
        LOGGER.exception("Domain enrichment failed: %s", error)
        return _unavailable()
