# 🎣 Phishing URL Detector

A rule-based phishing URL analyzer built in **Python + Flask**, designed to detect common phishing indicators in suspicious URLs using heuristic analysis.

The project identifies red flags such as typosquatting, brand impersonation, suspicious top-level domains, hosting-platform abuse, URL obfuscation techniques, and generic phishing keywords to estimate the likelihood that a URL is malicious.

Built as a hands-on cybersecurity project to explore detection engineering fundamentals, understand the strengths of rule-based detection, and identify where heuristic approaches reach their limits.

---

## 🚀 Features

- HTTPS / IP address / `@` symbol detection
- Typosquatting detection (e.g. `paypa1.com`)
- Brand impersonation detection
- Hosting-platform aware detection (AWS, Vercel, Netlify, GitHub Pages, etc.)
- Company-independent phishing keyword detection
- Gibberish/random domain detection
- Suspicious TLD detection
- URL shortener detection
- WHOIS domain age analysis
- Risk scoring engine (Low / Medium / High)
- SQLite scan history
- Flask-based web interface

---

## 🛠️ Tech Stack

- Python 3
- Flask
- SQLite
- HTML
- CSS
- tldextract
- python-whois

---

## 📁 Project Structure

```text
phishing-url-detector/

├── data/
│   ├── brands.py
│   ├── suspicious_tlds.py
│   ├── url_shorteners.py
│   ├── hosting_domains.py
│   └── phishing_keywords.py
│
├── templates/
│   └── index.html
│
├── app.py
├── detector.py
├── database.py
├── test_urls.py
├── test_batch.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/swaroop-pixel/phishing-url-detector.git
```

Move into the project

```bash
cd phishing-url-detector
```

Create a virtual environment

```bash
python -m venv venv
```

Activate it

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python app.py
```

Open your browser and visit

```
http://127.0.0.1:5000
```

---

## 🔍 Detection Features

The detector performs multiple independent security checks including:

- HTTPS verification
- Raw IP address detection
- Suspicious TLD detection
- URL shortener detection
- `@` symbol detection
- Excessive subdomain detection
- Excessive hyphen detection
- Random/gibberish domain detection
- Long URL detection
- Phishing keyword detection
- Typosquatting detection
- Brand impersonation detection
- WHOIS domain age analysis

Each detected indicator contributes to an overall risk score.

---

## 📊 Risk Scoring

| Score | Risk |
|-------:|------|
| 0 – 3 | 🟢 Low |
| 4 – 7 | 🟡 Medium |
| 8+ | 🔴 High |

Each phishing indicator contributes to the overall score.

The higher the score, the more suspicious the URL.

---

## 🧪 Testing

The detector has been tested using a mixture of:

- Real phishing URLs
- Legitimate websites
- Typosquatting examples
- Hosting-platform phishing URLs
- URL shorteners
- Randomly generated domains

Current small-scale testing achieved:

- ✅ 5 / 7 phishing URLs detected
- ✅ 0 / 8 false positives on tested legitimate URLs

---

## ⚠️ Current Limitations

This project is intentionally rule-based and therefore has some limitations.

- Clean-looking phishing domains may bypass detection.
- WHOIS lookups may fail because of rate limits or unavailable registration data.
- Phishing keyword detection currently supports English only.
- The detector analyzes only the URL, not the webpage content itself.
- No reputation services (VirusTotal, Google Safe Browsing) are currently integrated.

---

## 🚀 Future Improvements

Version 2

- Unicode / Punycode detection
- Suspicious path analysis
- Digit-ratio analysis
- URL entropy calculation
- Improved scoring engine

Version 3

- VirusTotal API integration
- Google Safe Browsing integration
- OpenPhish integration
- PhishTank integration
- DNS analysis
- SSL certificate analysis
- HTML page analysis

Version 4

- Machine Learning classifier
- Browser extension
- REST API
- Docker deployment

---

## 👨‍💻 Author

**Swaroop Morajkar**

Computer Engineering Graduate  
M.Sc. Cybersecurity Student  
Aspiring SOC Analyst & Security Engineer

GitHub:
https://github.com/swaroop-pixel

LinkedIn:
[text](https://www.linkedin.com/in/swaroop-morajkar-83071a260/)

---

## 📄 License

This project is licensed under the MIT License.

---

## ⚠️ Disclaimer

This project was developed for educational and cybersecurity research purposes.
It should not be considered a replacement for enterprise-grade phishing detection solutions and should be used alongside other security controls.