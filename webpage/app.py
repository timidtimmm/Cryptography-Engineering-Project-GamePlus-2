from flask import Flask, render_template, request, redirect, flash, session, url_for
import mysql.connector, hashlib
from dotenv import load_dotenv
import os
app = Flask(__name__)
app.secret_key = "your_secret_key"

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=%s", (user,))
        row = cur.fetchone()
        if row and row[0]==hash_pwd:
            session['username'] = user
            return redirect(url_for('welcome'))
        flash('Invalid credentials', 'danger')
        cur.close(); conn.close()
    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=='POST':
        user = request.form['username']
        pwd = request.form['password']
        hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s", (user,))
        if cur.fetchone(): flash('Username exists','danger')
        else:
            cur.execute("INSERT INTO users(username,password) VALUES(%s,%s)", (user,hash_pwd))
            conn.commit(); flash('Signup success','success')
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

if __name__=='__main__':
    app.run(debug=True)
