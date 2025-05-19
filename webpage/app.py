# app.py
from flask import Flask, render_template, request, redirect, flash, session, url_for
import mysql.connector, hashlib, os
from dotenv import load_dotenv

# ────────────────────────────────
# env & config
# ────────────────────────────────
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev_key')

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'secure_share')
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# ────────────────────────────────
# stub 2FA verifier ‑–– 之後由組員實作
# return True 表示驗證成功
# ────────────────────────────────
def verify_totp(username: str, code: str) -> bool:
    """⚠️ DEMO ONLY – 請替換成真正 TOTP / WebAuthn 邏輯"""
    return code == '123456'  # 临时測試碼

# ────────────────────────────────
# Routes
# ────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def login():
    """第一步：帳密驗證成功後 → 轉到 /verify 做 2FA"""
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=%s", (user,))
        row = cur.fetchone(); cur.close(); conn.close()
        if row and row[0] == hash_pwd:
            session['pending_user'] = user  # 暫存
            return redirect(url_for('verify'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """第二步：輸入 TOTP 或 WebAuthn 完成 2FA"""
    if 'pending_user' not in session:
        return redirect(url_for('login'))
    user = session['pending_user']
    if request.method == 'POST':
        code = request.form['code']
        if verify_totp(user, code):
            session['username'] = user
            session.pop('pending_user', None)
            return redirect(url_for('welcome'))
        flash('Invalid 2‑Factor code', 'danger')
    return render_template('verify.html', username=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s", (user,))
        if cur.fetchone():
            flash('Username exists', 'danger')
        else:
            cur.execute("INSERT INTO users(username,password) VALUES(%s,%s)", (user, hash_pwd))
            conn.commit(); flash('Signup success', 'success')
            return redirect(url_for('login'))
        cur.close(); conn.close()
    return render_template('signup.html')

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('welcome.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
