# Shared hosting/cloud platforms whose own domain name will always look like
# a "brand match" (e.g. amazonaws.com contains "amazon"). Detector.py only
# checks subdomains on these, not the platform's own domain.
KNOWN_INFRA_DOMAINS = {
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "googleusercontent.com",
    "herokuapp.com", "github.io", "vercel.app", "netlify.app", "pages.dev", "web.app",
}