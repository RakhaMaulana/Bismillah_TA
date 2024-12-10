from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import sqlite3
import hashlib
import BlindSig as bs
import random
import cryptomath
import os
import base64
from createdb import save_keys, save_voter, save_ballot, save_candidate, get_db_connection, get_existing_keys
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import string
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "50 per hour"],
    storage_uri="memory://"
)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashlib.sha256(password.encode()).hexdigest()))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('register_candidate'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/register_candidate', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register_candidate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        candidate_class = request.form['class']
        photo = request.files['photo']
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(photo_filename)
            save_candidate(name, photo_filename, candidate_class)
            flash('Candidate registered successfully')
        else:
            flash('Invalid file type')
    return render_template('register_candidate.html')

@app.route('/register_voter', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def register_voter():
    if request.method == 'POST':
        id_number = request.form['id_number']
        photo_data = request.form['photo']
        photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f"{id_number}.jpg"))

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
@limiter.limit("100 per minute")
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


@app.route('/vote', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def vote():
    if request.method == 'POST':
        candidate_id = request.form['candidate']
        id_number = request.form['id_number']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT approved FROM voters WHERE id_number = ?", (id_number,))
        voter = c.fetchone()
        if not voter:
            flash('Voter not found')
            return redirect(url_for('vote'))
        if voter[0] == 0:
            flash('Voter not approved')
            return redirect(url_for('vote'))
        c.execute("SELECT * FROM ballots WHERE concatenated_message LIKE ?", (id_number + '%',))
        if c.fetchone():
            flash('Vote already cast')
            return redirect(url_for('vote'))

        existing_keys = get_existing_keys()
        if existing_keys:
            n, e, _ = existing_keys
            signer = bs.Signer()
            signer.public_key = {'n': n, 'e': e}
            signer.private_key = {'d': _}
        else:
            signer = bs.Signer()
            public_key = signer.get_public_key()
            n = public_key['n']
            e = public_key['e']
            _ = signer.private_key['d']
            save_keys(n, e, _)  # Save keys to the database

        x = random.randint(1, n)
        concat_message = str(candidate_id) + str(x)
        message_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        message_hash = int(message_hash, 16)
        voter = bs.Voter(n, "y")
        blind_message = voter.blind_message(message_hash, n, e)
        signed_blind_message = signer.sign_message(blind_message, voter.get_eligibility())
        signed_message = voter.unwrap_signature(signed_blind_message, n)
        save_ballot(x, concat_message, message_hash, blind_message, signed_blind_message, signed_message)
        flash('Vote cast successfully')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, photo, class FROM candidates")
    candidates = c.fetchall()
    conn.close()
    return render_template('vote.html', candidates=candidates)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host='0.0.0.0', port=5000, debug=True)