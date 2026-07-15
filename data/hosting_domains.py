"""
Shared hosting/cloud platform domains, grouped by provider.

These are legitimate infrastructure domains whose own name will always look
like a "brand match" (e.g. amazonaws.com contains "amazon"). detector.py uses
this set to check only the subdomain (attacker-controlled part) rather than
the domain itself on these platforms - see KNOWN_INFRA_DOMAINS usage in 9b.

Convention: lowercase, registrable domain only.
"""

# --- Amazon Web Services --------------------------------------------------------
AWS = {
    "amazonaws.com",
    "cloudfront.net",
    "s3.amazonaws.com",
    "elasticbeanstalk.com",
    "awsapps.com",
    "execute-api.amazonaws.com",
}

# --- Microsoft Azure -------------------------------------------------------------
AZURE = {
    "azurewebsites.net",
    "azureedge.net",
    "blob.core.windows.net",
    "azurefd.net",
    "cloudapp.net",
    "trafficmanager.net",
}

# --- Google Cloud Platform / Firebase-adjacent ------------------------------------
GOOGLE_CLOUD = {
    "googleusercontent.com",
    "web.app",
    "firebaseapp.com",
    "appspot.com",
    "run.app",
    "cloudfunctions.net",
}

# --- Cloudflare Pages/Workers ------------------------------------------------------
CLOUDFLARE = {
    "pages.dev",
    "workers.dev",
    "cloudflare-ipfs.com",
    "trycloudflare.com",
}

# --- Netlify -------------------------------------------------------------------------
NETLIFY = {
    "netlify.app",
    "netlify.com",
}

# --- Vercel --------------------------------------------------------------------------
VERCEL = {
    "vercel.app",
    "now.sh",
}

# --- GitHub Pages ----------------------------------------------------------------------
GITHUB_PAGES = {
    "github.io",
}

# --- Render --------------------------------------------------------------------------------
RENDER = {
    "onrender.com",
}

# --- Railway ------------------------------------------------------------------------------
RAILWAY = {
    "railway.app",
    "up.railway.app",
}

# --- DigitalOcean App Platform --------------------------------------------------------------
DIGITALOCEAN = {
    "ondigitalocean.app",
    "digitaloceanspaces.com",
}

# --- Hetzner -----------------------------------------------------------------------------------
HETZNER = {
    "your-server.de",
    "hetzner.com",
    "hetzner.app",
}

# --- Linode / Akamai -----------------------------------------------------------------------------
LINODE = {
    "linodeobjects.com",
    "linode.com",
    "members.linode.com",
}

# --- Firebase (kept distinct from GOOGLE_CLOUD for granularity) -------------------------------------
FIREBASE = {
    "firebaseio.com",
}

# --- Fastly CDN ---------------------------------------------------------------------------------------
FASTLY = {
    "fastly.net",
    "fastly-edge.com",
    "a.ssl.fastly.net",
}

# --- Oracle Cloud ------------------------------------------------------------------------------------------
ORACLE = {
    "oraclecloud.com",
    "objectstorage.oraclecloud.com",
}

# --- BunnyCDN ------------------------------------------------------------------------------------------------
BUNNYCDN = {
    "b-cdn.net",
    "bunnycdn.com",
}

# --- Provider registry ---------------------------------------------------------------------------------------
INFRA_BY_PROVIDER = {
    "AWS": AWS,
    "AZURE": AZURE,
    "GOOGLE_CLOUD": GOOGLE_CLOUD,
    "CLOUDFLARE": CLOUDFLARE,
    "NETLIFY": NETLIFY,
    "VERCEL": VERCEL,
    "GITHUB_PAGES": GITHUB_PAGES,
    "RENDER": RENDER,
    "RAILWAY": RAILWAY,
    "DIGITALOCEAN": DIGITALOCEAN,
    "HETZNER": HETZNER,
    "LINODE": LINODE,
    "FIREBASE": FIREBASE,
    "FASTLY": FASTLY,
    "ORACLE": ORACLE,
    "BUNNYCDN": BUNNYCDN,
}

# --- Flattened export for backward-compatible detector.py use (kept as a set,
# matching current detector.py's `full_domain.lower() in KNOWN_INFRA_DOMAINS`) ---
KNOWN_INFRA_DOMAINS = set().union(*INFRA_BY_PROVIDER.values())