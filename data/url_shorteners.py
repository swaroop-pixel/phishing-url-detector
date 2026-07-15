"""
URL shortener domains, grouped by how commonly they appear in real traffic.
Popularity tiers exist so detector.py (or a future scoring pass) can
eventually weight a major shortener differently from an obscure one, without
restructuring the data again later.

Convention: lowercase, registrable domain only.
"""

# --- High-traffic, globally recognized shorteners ---------------------------
MAJOR_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "bl.ink", "dub.co", "kutt.it", "polr.me", "shorte.st", "adf.ly",
    "sniply.io", "bit.do", "clck.ru", "is.gd", "v.gd", "vzturl.com", "chilp.it",
    "yfrog.com", "migre.me", "ff.im", "url4.eu", "twurl.nl", "sn.im", "qr.ae"
}

# --- Moderately common, still frequently seen in phishing campaigns ----------
MEDIUM_SHORTENERS = {
    "ow.ly", "rebrand.ly", "buff.ly", "clicky.me", "po.st", "b.link", "linkvertise.com",
    "shrtco.de", "tinyone.co", "shortcm.li", "switchere.com", "tny.im", "urlr.me",
    "s.id", "gg.gg", "murl.com", "cutt.us", "git.io", "qr.net", "short.io",
    "hub.vg", "lurl.com", "plu.sh", "zi.ma", "urlbee.com", "tiny.pl", "zpr.io",
    "hideuri.com", "shorturl.com", "mylnk.gq", "1url.cz", "2m.lc", "307.to", "urli.st"
}

# --- Older/legacy services, still occasionally active ------------------------
LEGACY_SHORTENERS = {
    "tr.im", "cli.gs", "u.nu", "short.to", "budurl.com", "kl.am", "idek.net",
    "shrinkster.com", "fed.al", "x.co", "go2.me", "post.ly", "just.as", "bkite.com",
    "hurl.ws", "snipurl.com", "snipr.com", "snurl.com", "doiop.com", "twitthis.com",
    "rub.im", "a.gg", "pnt.me", "icanhaz.com", "to.ly", "fly2.ws", "eepurl.com",
    "hops.me", "dft.ba", "dfl8.me", "ro.im", "sk.cx", "xr.com"
}

# --- Shorteners embedded in/native to social platforms ------------------------
SOCIAL_SHORTENERS = {
    "t.co", "fb.me", "lnkd.in", "t.me", "wa.me", "youtu.be", "instagr.am",
    "ig.me", "pin.it", "twitch.tv", "m.me", "discord.gg", "dis.gd", "spoti.fi",
    "amzn.to", "ebay.to", "nyti.ms", "wapo.st", "wsj.com", "bloom.bg", "cnn.it"
}

# --- Tier registry -------------------------------------------------------------
SHORTENERS_BY_TIER = {
    "MAJOR_SHORTENERS": MAJOR_SHORTENERS,
    "MEDIUM_SHORTENERS": MEDIUM_SHORTENERS,
    "LEGACY_SHORTENERS": LEGACY_SHORTENERS,
    "SOCIAL_SHORTENERS": SOCIAL_SHORTENERS,
}

# --- Flattened export for backward-compatible detector.py use ---
URL_SHORTENERS = set().union(*SHORTENERS_BY_TIER.values())