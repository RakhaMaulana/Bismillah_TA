from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import sqlite3
import hashlib
import BlindSig as bs
import random
import cryptomath
import os
import base64
from createdb import save_keys, save_voter, save_ballot, save_candidate, get_db_connection
from wtforms import Form, StringField, PasswordField, validators
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'your_csrf_secret_key'

def get_existing_keys():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()
    conn.close()
    if key:
        n, e, d = int(key[0]), int(key[1]), int(key[2])
        return n, e, d
    else:
        return None

def is_ip_whitelisted(ip_address):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM whitelisted_ips WHERE ip_address = ?", (ip_address,))
    result = c.fetchone()
    conn.close()
    return result is not None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('register_candidate'))
        else:
            flash('Invalid credentials')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/register_candidate', methods=['GET', 'POST'])
def register_candidate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        candidate_class = request.form['class']
        photo = request.files['photo']
        photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], f"candidate_{name}.jpg")
        photo.save(photo_filename)
        save_candidate(name, photo_filename, candidate_class)
        flash('Candidate registered successfully')
    return render_template('register_candidate.html')

@app.route('/register_voter', methods=['GET', 'POST'])
def register_voter():
    if request.method == 'POST':
        id_number = request.form['id_number']
        photo_data = request.form['photo']
        photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], f"{id_number}.jpg")

        # Decode the base64 image data and save it as a file
        photo_data = photo_data.split(',')[1]
        with open(photo_filename, "wb") as fh:
            fh.write(base64.b64decode(photo_data))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM voters WHERE id_number = ?", (id_number,))
        existing_voter = c.fetchone()
        if existing_voter:
            flash('ID number already registered')
            return redirect(url_for('register_voter'))
        digital_signature = hashlib.sha256(photo_data.encode()).hexdigest()
        save_voter(id_number, digital_signature, photo_filename)
        flash('Voter registered successfully. Awaiting admin approval.')
    return render_template('register_voter.html')

@app.route('/approve_voter', methods=['GET', 'POST'])
def approve_voter():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        voter_id = request.form['voter_id']
        c.execute("UPDATE voters SET approved = 1 WHERE id = ?", (voter_id,))
        conn.commit()
        flash('Voter approved successfully')
    c.execute("SELECT id, id_number, photo FROM voters WHERE approved = 0")
    voters = c.fetchall()
    conn.close()
    return render_template('approve_voter.html', voters=voters)

@app.route('/manage_ips', methods=['GET', 'POST'])
def manage_ips():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        action = request.form['action']
        if action == 'add':
            c.execute("INSERT INTO whitelisted_ips (ip_address) VALUES (?)", (ip_address,))
            flash('IP address added to whitelist')
        elif action == 'remove':
            c.execute("DELETE FROM whitelisted_ips WHERE ip_address = ?", (ip_address,))
            flash('IP address removed from whitelist')
        conn.commit()
    c.execute("SELECT ip_address FROM whitelisted_ips")
    whitelisted_ips = c.fetchall()
    conn.close()
    return render_template('manage_ips.html', whitelisted_ips=whitelisted_ips)

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if not is_ip_whitelisted(request.remote_addr):
        return render_template('403.html'), 403  # Render halaman error

    if request.method == 'POST':
        candidate_id = request.form['candidate']
        id_number = request.form['id_number']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT approved FROM voters WHERE id_number = ?", (id_number,))
        voter = c.fetchone()
        if not voter:
            flash('Voter not registered')
            return redirect(url_for('vote'))
        if voter[0] == 0:
            flash('Voter not approved by admin')
            return redirect(url_for('vote'))
        c.execute("SELECT * FROM ballots WHERE concatenated_message LIKE ?", (id_number + '%',))
        if c.fetchone():
            flash('Voter has already voted')
            return redirect(url_for('vote'))
        existing_keys = get_existing_keys()
        if existing_keys:
            n, e, d = existing_keys
            signer = bs.Signer()
            signer.publicKey = {'n': n, 'e': e}
            signer.privateKey = {'d': d}
        else:
            signer = bs.Signer()
            publicKey = signer.getPublicKey()
            n = publicKey['n']
            e = publicKey['e']
            d = signer.privateKey['d']
            save_keys(n, e, d)  # Save keys to the database

        x = random.randint(1, n)
        concat_message = str(candidate_id) + str(x)
        message_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        message_hash = int(message_hash, 16)
        voter = bs.Voter(n, "y")
        blindMessage = voter.blindMessage(message_hash, n, e)
        signedBlindMessage = signer.signMessage(blindMessage, voter.getEligibility())
        signedMessage = voter.unwrapSignature(signedBlindMessage, n)
        save_ballot(x, concat_message, message_hash, blindMessage, signedBlindMessage, signedMessage)
        flash('Vote cast successfully')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, photo, class FROM candidates")
    candidates = c.fetchall()
    conn.close()
    return render_template('vote.html', candidates=candidates)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://code.jquery.com"
    return response

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host='0.0.0.0', port=5000, debug=True)