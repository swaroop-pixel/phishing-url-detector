"""
TLDs grouped by realistic abuse level, based on publicly documented spam/
phishing-abuse research (e.g. Spamhaus/Interisle "World's Most Abused TLDs"
style reporting), not gut feeling. Being flagged here should mean "elevated
base rate of abuse," never "guaranteed malicious" - a TLD alone should
always be a weak signal that combines with other checks, not a standalone
verdict.

Do not add a TLD here just because it's unfamiliar - many legitimate
regional/niche TLDs (.de, .in, .jp, etc.) are intentionally excluded, since
this is meant to be an abuse-rate signal, not an "uncommon TLD" list.

Convention: lowercase, includes the leading dot (e.g. ".xyz").
"""

# --- Consistently top-ranked in independent domain-abuse reports --------------
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".gq", ".tk", ".ml", ".ga", ".cf", ".bid", ".date", 
    ".win", ".download", ".loan", ".racing", ".vip", ".party", ".science", 
    ".study", ".country", ".stream", ".kim", ".men", ".mom", ".xin"
}

# --- Elevated abuse rate, but also has meaningful legitimate use --------------
MODERATE_RISK_TLDS = {
    ".club", ".work", ".click", ".link", ".live", ".co", ".info", ".online", 
    ".site", ".space", ".website", ".tech", ".store", ".me", ".cc", ".asia", 
    ".biz", ".mobi", ".tokyo", ".run", ".today", ".email", ".agency", ".systems"
}

# --- Newer generic TLDs with limited reputation history / cheap registration --
NEW_GENERIC_TLDS = {
    ".icu", ".cfd", ".sbs", ".cyou", ".monster", ".fit", ".buzz", ".best", 
    ".fun", ".uno", ".yachts", ".homes", ".bids", ".gdn", ".cam", ".rest", 
    ".makeup", ".skin", ".quest", ".bond", ".pics", ".beauty", ".digital"
}

# --- Risk-tier registry ---------------------------------------------------------
TLDS_BY_RISK = {
    "HIGH_RISK_TLDS": HIGH_RISK_TLDS,
    "MODERATE_RISK_TLDS": MODERATE_RISK_TLDS,
    "NEW_GENERIC_TLDS": NEW_GENERIC_TLDS,
}

# --- Flattened export for backward-compatible detector.py use ---
SUSPICIOUS_TLDS = set().union(*TLDS_BY_RISK.values())