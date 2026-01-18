from flask import Flask, render_template, redirect, url_for
from core.db import session, RequestLog, BlacklistRule

app = Flask(__name__)

@app.route('/')
def dashboard():
    logs = session.query(RequestLog).order_by(RequestLog.timestamp.desc()).limit(50).all()
    return render_template('dashboard.html', logs=logs)

@app.route('/ban/<path:ip>')
def ban_ip(ip):
    if not session.query(BlacklistRule).filter_by(value=ip).first():
        session.add(BlacklistRule(rule_type='ip', value=ip))
        session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)