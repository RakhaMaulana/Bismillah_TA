import socket
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import hashlib
import BlindSig as bs
import secrets
import base64
from createdb import save_keys, save_voter, save_ballot, save_candidate, get_db_connection, get_existing_keys
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import uuid
from dotenv import load_dotenv
from Recap import recap_votes
from markupsafe import escape

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB max file size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["40000000000 per hour"],
    storage_uri="memory://"
)


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def apply_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
@limiter.limit("20000000 per minute")
def login():
    username = escape(request.form['username'])
    password = escape(request.form['password'])
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashlib.sha256(password.encode()).hexdigest()))
    user = c.fetchone()
    conn.close()
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        return redirect(url_for('register_candidate_page'))

    flash('Invalid credentials')
    return redirect(url_for('login_page'))


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/register_candidate', methods=['GET'])
def register_candidate_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('register_candidate.html')


@app.route('/register_candidate', methods=['POST'])
@limiter.limit("20000000 per minute")
def register_candidate():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    name = escape(request.form['name'])
    candidate_class = escape(request.form['class'])
    photo = request.files['photo']
    if photo and allowed_file(photo.filename):
        filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(photo.filename)[1])
        photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_filename)
        save_candidate(name, photo_filename, candidate_class)
        flash('Candidate registered successfully')
    else:
        flash('Invalid file type')
    return redirect(url_for('register_candidate_page'))


@app.route('/register_voter', methods=['GET'])
def register_voter_page():
    return render_template('register_voter.html', token=None)


@app.route('/register_voter', methods=['POST'])
@limiter.limit("20000000 per minute")
def register_voter():
    id_number = escape(request.form['id_number'])
    photo_data = request.form['photo']
    photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f"{id_number}.jpg"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM voters WHERE id_number = ?", (id_number,))
    existing_voter = c.fetchone()
    if existing_voter:
        if existing_voter['approved'] == 0:
            flash('ID number already registered. Awaiting admin approval.')
        else:
            flash('ID number already registered and approved.')
        return redirect(url_for('register_voter_page'))

    photo_data = photo_data.split(',')[1]
    with open(photo_filename, "wb") as fh:
        fh.write(base64.b64decode(photo_data))

    digital_signature = hashlib.sha256(photo_data.encode()).hexdigest()
    token = save_voter(id_number, digital_signature, photo_filename)
    flash('Voter registered successfully. Awaiting admin approval.')
    return render_template('register_voter.html', token=token)


@app.route('/approve_voter', methods=['GET'])
def approve_voter_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, id_number, photo FROM voters WHERE approved = 0")
    voters = c.fetchall()
    conn.close()
    return render_template('approve_voter.html', voters=voters)


@app.route('/approve_voter', methods=['POST'])
@limiter.limit("20000000 per minute")
def approve_voter():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    c = conn.cursor()
    voter_id = escape(request.form['voter_id'])
    action = escape(request.form['action'])
    if action == 'approve':
        c.execute("UPDATE voters SET approved = 1 WHERE id = ?", (voter_id,))
        flash('Voter approved successfully')
    elif action == 'reject':
        c.execute("DELETE FROM voters WHERE id = ?", (voter_id,))
        flash('Voter rejected successfully')
    conn.commit()
    conn.close()
    return redirect(url_for('approve_voter_page'))


@app.route('/vote', methods=['GET'])
def vote_page():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, photo, class FROM candidates")
    candidates = c.fetchall()
    conn.close()
    return render_template('vote.html', candidates=candidates, no_candidates=len(candidates) == 0)


@app.route('/vote', methods=['POST'])
@limiter.limit("20000000 per minute")
def vote():
    candidate_id = escape(request.form['candidate'])
    token = escape(request.form['token'])
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_number, approved, token_used FROM voters WHERE token = ?", (hashed_token,))
    voter = c.fetchone()
    if not voter:
        flash('Invalid token')
        return redirect(url_for('vote_page'))
    id_number, approved, token_used = voter
    if approved == 0:
        flash('Voter not approved')
        return redirect(url_for('vote_page'))
    if token_used == 1:
        flash('Token already used')
        return redirect(url_for('vote_page'))
    c.execute("SELECT * FROM ballots WHERE concatenated_message LIKE ?", (id_number + '%',))
    if c.fetchone():
        flash('Vote already cast')
        return redirect(url_for('vote_page'))

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

    x = secrets.randbelow(n - 1) + 1
    concat_message = str(candidate_id) + str(x)
    message_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
    message_hash = int(message_hash, 16)
    voter = bs.Voter(n, "y")
    blind_message = voter.blind_message(message_hash, n, e)
    signed_blind_message = signer.sign_message(blind_message, voter.get_eligibility())
    signed_message = voter.unwrap_signature(signed_blind_message, n)
    save_ballot(x, concat_message, message_hash, blind_message, signed_blind_message, signed_message)

    c.execute("UPDATE voters SET token_used = 1 WHERE token = ?", (hashed_token,))
    conn.commit()
    conn.close()

    flash('Vote cast successfully')
    return redirect(url_for('vote_page'))


@app.route('/recap', methods=['GET'])
@limiter.limit("20000000 per minute")
def recap():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    vote_counts = recap_votes()
    return render_template('recap.html', vote_counts=vote_counts)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        outer_local_ip = s.getsockname()[0]
        s.close()
        return outer_local_ip
    except Exception as e:
        print(f"Error detecting local IP: {e}")
        return "127.0.0.1"


if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    cert_path = "dev.certificate.crt"
    key_path = "dev.private.key"

    local_ip = get_local_ip()
    print(f"Running Flask app on IP: {local_ip}")

    app.run(host=local_ip, port=5000, ssl_context=(cert_path, key_path))
