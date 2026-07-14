import whois
import re
import tldextract
from datetime import datetime

from data.brands import POPULAR_DOMAINS
from data.suspicious_tlds import SUSPICIOUS_TLDS
from data.url_shorteners import URL_SHORTENERS
from data.hosting_domains import KNOWN_INFRA_DOMAINS
from data.phishing_keywords import PHISHING_KEYWORDS

# Use the bundled snapshot instead of fetching the public suffix list
# over the network on every run (avoids slow/failing HTTP calls + noisy tracebacks)
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Set to True if you want to see WHY a WHOIS lookup failed (timeout, no data, etc.)
VERBOSE = False


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


def check_domain_age(domain_with_suffix, verbose=False):
    """Returns age in days, or None if lookup fails."""
    try:
        w = whois.whois(domain_with_suffix)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            if verbose:
                print(f"    [debug] WHOIS returned no creation date for {domain_with_suffix}")
            return None

        age_days = (datetime.now() - creation_date).days
        return age_days
    except Exception as e:
        if verbose:
            print(f"    [debug] WHOIS lookup failed for {domain_with_suffix}: {e}")
        return None


def check_url(raw_url):
    flags = []
    score = 0

    url = raw_url.strip()

    # 0a. Flag internal whitespace
    if " " in url:
        flags.append("URL contains spaces - likely malformed or manually typed incorrectly")
        score += 2

    # 0b. Assume http if no scheme given
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # 1. Check HTTPS
    if not url.startswith("https://"):
        flags.append("No HTTPS - connection is not encrypted")
        score += 2

    # 2. Check for IP address instead of domain name
    ip_pattern = r"://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    if re.search(ip_pattern, url):
        flags.append("Uses raw IP address instead of a domain name")
        score += 3

    # 3. Extract domain parts
    extracted = _tld_extractor(url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    full_domain = f"{domain}.{suffix}" if suffix else domain

    # 4. Check suspicious TLD
    if any(url.lower().find(tld) != -1 for tld in SUSPICIOUS_TLDS):
        flags.append("Suspicious top-level domain detected")
        score += 2

    # 5. Check URL shorteners - exact registered-domain match, not raw substring
    # (avoids false positives like reddit.com containing "t.co")
    if full_domain.lower() in URL_SHORTENERS:
        flags.append("URL shortener detected - real destination is hidden")
        score += 2

    # 6. Check for @ symbol
    if "@" in url:
        flags.append("Contains '@' symbol - can be used to disguise the real destination")
        score += 3

    # 7. Check excessive subdomains
    if subdomain.count(".") >= 2:
        flags.append("Excessive number of subdomains")
        score += 1

    # 8. Check excessive hyphens across domain AND subdomain (hosting-platform
    # phishing like fake-bank.vercel.app puts the fake name in the subdomain)
    combined_for_hyphens = f"{subdomain}.{domain}" if subdomain else domain
    if combined_for_hyphens.count("-") >= 2:
        flags.append("Excessive hyphens in domain/subdomain")
        score += 1

    # 8b. Gibberish/randomly-generated domain check
    if looks_like_gibberish(domain):
        flags.append("Domain name looks randomly generated rather than a real word/brand")
        score += 3

    # 8c. URL length check
    url_length = len(url)
    if url_length > 150:
        flags.append(f"URL is unusually long ({url_length} characters) - often used to obscure the real destination")
        score += 3
    elif url_length > 100:
        flags.append(f"URL is longer than typical ({url_length} characters)")
        score += 1

    # 8d. Generic phishing-keyword check (company-agnostic)
    searchable_text = url.lower()
    keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in searchable_text]
    if keyword_hits:
        contribution = min(len(keyword_hits), 3)
        shown = ", ".join(keyword_hits[:3])
        extra = f" (+{len(keyword_hits) - 3} more)" if len(keyword_hits) > 3 else ""
        flags.append(f"Contains phishing-style keyword(s): {shown}{extra}")
        score += contribution

    # 9. Typosquatting check - split on hyphens to catch "sparkase-hamm" style patterns
    domain_words = domain.lower().split("-")
    typosquat_found = False
    for popular in POPULAR_DOMAINS:
        popular_name = popular.split(".")[0]
        for word in domain_words:
            distance = levenshtein_distance(word, popular_name)
            if 0 < distance <= 2 and len(word) >= 4:
                flags.append(f"Domain looks suspiciously similar to '{popular}' (possible typosquatting)")
                score += 5
                typosquat_found = True
                break
        if typosquat_found:
            break

    # 9b. Brand impersonation check across domain AND subdomain, with an
    # allowlist for hosting platforms so their own name isn't false-flagged
    if full_domain.lower() in KNOWN_INFRA_DOMAINS:
        lookup_text = subdomain.lower()
    else:
        lookup_text = f"{subdomain}.{domain}".lower()

    for popular in POPULAR_DOMAINS:
        popular_name = popular.split(".")[0]
        if popular_name in lookup_text and domain.lower() != popular_name:
            flags.append(f"Contains brand name '{popular_name}' but isn't the real site (possible impersonation)")
            score += 4
            break

    # 10. Domain age check
    age_days = check_domain_age(full_domain, verbose=VERBOSE)
    if age_days is not None:
        if age_days < 30:
            flags.append(f"Domain registered only {age_days} days ago - very new domains are high risk")
            score += 4
        elif age_days < 180:
            flags.append(f"Domain registered {age_days} days ago - relatively new")
            score += 2

    # Determine risk level
    if score >= 8:
        risk = "High"
    elif score >= 4:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "url": raw_url,
        "score": score,
        "risk": risk,
        "flags": flags
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "http://paypa1-secure-login.xyz/account",
        "https://bit.ly/3xample",
        "http://www.faceb00k.com@evil.com/login",
        "googgle.com.in",
        "sslkislksd.com",
        "https://allegrolokalnie.lato-2026-523924.click",
        "https://sparkase-hamm.de/",
        "https://itauclientes-nqxep046f-gamero-galons-projects.vercel.app/",
        "https://www.reddit.com",
        "http://sbi-verify-account.xyz/login/confirm-details",
    ]

    for u in test_urls:
        result = check_url(u)
        print("=" * 60)
        print(f"URL:  {result['url']}")
        print(f"Risk: {result['risk']}  (score: {result['score']})")
        for f in (result["flags"] or ["(no flags raised)"]):
            print(f"  - {f}")
    print("=" * 60)