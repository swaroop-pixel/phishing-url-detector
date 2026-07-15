from flask import Flask, render_template, request
from detector import check_url
from domain_info import get_domain_information
from database import init_db, save_scan, get_recent_scans

app = Flask(__name__)
init_db()

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            result = check_url(url)
            result['meter_percent'] = min(int(result['score'] / 15 * 100), 100)

            # Domain Information panel metadata - collected separately from
            # phishing detection. get_domain_information() never raises, but
            # this try/except is a second line of defense: even an
            # unexpected failure here can never stop the scan itself from
            # completing or being saved to history.
            try:
                domain_info = get_domain_information(url)
            except Exception:
                domain_info = {
                    "domain": "Unavailable", "subdomain": "Unavailable", "suffix": "Unavailable",
                    "registrar": "Unavailable", "created_date": "Unavailable", "expiry_date": "Unavailable",
                    "country": "Unavailable", "ip_address": "Unavailable", "hosting_provider": "Unavailable",
                    "ssl_status": "Unavailable", "whois_available": False,
                }

            result.update(domain_info)
            # index.html's Domain Information panel reads these short
            # aliases directly (result.created, result.ip, etc.) - set them
            # so the existing template needs no changes.
            result['created'] = domain_info['created_date']
            result['expiry'] = domain_info['expiry_date']
            result['ip'] = domain_info['ip_address']
            result['hosting'] = domain_info['hosting_provider']
            result['ssl'] = domain_info['ssl_status']

            save_scan(result['url'], result['risk'], result['score'])

    history = get_recent_scans(10)
    return render_template('index.html', result=result, history=history)

if __name__ == '__main__':
    app.run(debug=True)