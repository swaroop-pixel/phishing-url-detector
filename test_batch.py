import whois
import re
import tldextract
from datetime import datetime

# Use the bundled snapshot instead of fetching the public suffix list
# over the network on every run (avoids slow/failing HTTP calls + noisy tracebacks)
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Set to True if you want to see WHY a WHOIS lookup failed (timeout, no data, etc.)
VERBOSE = False

# A small list of well-known domains to check for typosquatting
POPULAR_DOMAINS = [
    "google.com", "paypal.com", "amazon.com", "facebook.com",
    "microsoft.com", "apple.com", "netflix.com", "instagram.com",
    "linkedin.com", "bankofamerica.com",
    "sparkasse.de", "allegro.pl", "itau.com.br", "hdfcbank.com",
    "chase.com", "wellsfargo.com", "dhl.com", "fedex.com"
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".top", ".club", ".gq", ".work", ".click"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]


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

    Real words rarely have more than 2-3 consonants in a row (English brand
    names like 'microsoft', 'facebook', 'instagram' all stay at 2-3). Random
    strings routinely hit 4+. This turned out to be a far more reliable signal
    than Shannon entropy, which was fooled by repeated letters in gibberish
    strings (e.g. 'sslkislksd' scored LOWER entropy than 'microsoft' despite
    being obvious gibberish to a human reader).
    """
    if len(domain) < 6:
        return False  # too short to judge reliably

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

    # 0a. Flag internal whitespace - real links never contain raw spaces
    if " " in url:
        flags.append("URL contains spaces - likely malformed or manually typed incorrectly")
        score += 2

    # 0b. If no scheme given, assume http so parsing/regex checks still work
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

    # 5. Check URL shorteners - compare against the actual registered domain
    # (not a raw substring match, which wrongly flags things like reddit.com
    # containing the literal substring "t.co")
    if full_domain.lower() in URL_SHORTENERS:
        flags.append("URL shortener detected - real destination is hidden")
        score += 2

    # 6. Check for @ symbol (used to trick browsers/users)
    if "@" in url:
        flags.append("Contains '@' symbol - can be used to disguise the real destination")
        score += 3

    # 7. Check excessive subdomains
    if subdomain.count(".") >= 2:
        flags.append("Excessive number of subdomains")
        score += 1

    # 8. Check excessive hyphens (common in fake domains like paypal-secure-login.com)
    # Checked across domain AND subdomain - on hosting platforms (vercel.app, netlify.app,
    # github.io) the fake brand name sits in the subdomain, not the domain, since attackers
    # don't control the actual registered domain there.
    combined_for_hyphens = f"{subdomain}.{domain}" if subdomain else domain
    if combined_for_hyphens.count("-") >= 2:
        flags.append("Excessive hyphens in domain/subdomain")
        score += 1

    # 8b. Gibberish/randomly-generated domain check
    if looks_like_gibberish(domain):
        flags.append("Domain name looks randomly generated rather than a real word/brand")
        score += 3

    # 9. Typosquatting check against popular domains
    # Split on hyphens so we catch patterns like "sparkase-hamm" or "paypa1-secure-login"
    # where a typosquatted brand name is combined with an extra descriptive word.
    domain_words = domain.lower().split("-")
    typosquat_found = False
    for popular in POPULAR_DOMAINS:
        popular_name = popular.split(".")[0]  # e.g. "paypal" from "paypal.com"
        for word in domain_words:
            distance = levenshtein_distance(word, popular_name)
            if 0 < distance <= 2 and len(word) >= 4:
                flags.append(f"Domain looks suspiciously similar to '{popular}' (possible typosquatting)")
                score += 5
                typosquat_found = True
                break
        if typosquat_found:
            break

    # 9b. Check if a popular brand name appears inside a longer/different domain OR subdomain
    # (hosting-platform phishing like fake-bank.vercel.app hides the brand in the subdomain)
    lookup_text = f"{subdomain}.{domain}".lower()
    for popular in POPULAR_DOMAINS:
        popular_name = popular.split(".")[0]
        if popular_name in lookup_text and domain.lower() != popular_name:
            flags.append(f"Contains brand name '{popular_name}' but isn't the real site (possible impersonation)")
            score += 4
            break

    # 10. Domain age check (freshly registered domains are a strong phishing signal)
    age_days = check_domain_age(full_domain, verbose=VERBOSE)
    if age_days is not None:
        if age_days < 30:
            flags.append(f"Domain registered only {age_days} days ago - very new domains are high risk")
            score += 4
        elif age_days < 180:
            flags.append(f"Domain registered {age_days} days ago - relatively new")
            score += 2
    # If age_days is None, we couldn't determine it - don't penalize, just skip

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


# Test it out directly when running this file
if __name__ == "__main__":
    test_urls =  [
    "https://allegrolokalnie.lato-2026-523924.click",
    "https://sparkase-hamm.de/",
    "http://allegro.lato-2026-523924.click",
    "https://facet-fjord-mill-ef66.s3.us-west-2.amazonaws.com/",  # <- re-copy full URL, this looks cut off
    "https://www.pneustoore.com/carrinho/finalizar/",              # <- re-copy full URL, this looks cut off
    "https://vercel.com/login",                                     # <- re-copy full URL, this looks cut off
    "https://itauclientes-nqxep046f-gamero-galons-projects.vercel.app/",  # <- re-copy full URL, this looks cut off
]

    for u in test_urls:
        result = check_url(u)
        print("=" * 60)
        print(f"URL:  {result['url']}")
        print(f"Risk: {result['risk']}  (score: {result['score']})")
        if result["flags"]:
            for f in result["flags"]:
                print(f"  - {f}")
        else:
            print("  (no flags raised)")
    print("=" * 60)