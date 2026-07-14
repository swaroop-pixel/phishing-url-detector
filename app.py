from flask import Flask, render_template, request
from detector import check_url
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
            save_scan(result['url'], result['risk'], result['score'])

    history = get_recent_scans(10)
    return render_template('index.html', result=result, history=history)

if __name__ == '__main__':
    app.run(debug=True)