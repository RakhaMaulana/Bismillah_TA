import socket
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
import hashlib
import BlindSig as bs
import secrets
import base64
from createdb import save_keys, save_voter, save_ballot, save_candidate, get_db_connection, get_existing_keys, get_all_candidates
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
import uuid
from dotenv import load_dotenv
from Recap import recap_votes
from markupsafe import escape
import time
from flask import Response
import json


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
    app,
    default_limits=["40000000000 per hour"],
    storage_uri="memory://"
)


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def apply_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=300; includeSubDomains; preload"
    # response.headers["Cache-Control"] = "no-store"
    # response.headers["Pragma"] = "no-cache"
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
    candidate_type = escape(request.form['candidate_type'])
    photo = request.files['photo']
    if photo and allowed_file(photo.filename):
        filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(photo.filename)[1])
        photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_filename)
        save_candidate(name, 'uploads/' + filename, candidate_class, candidate_type)
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
    filename = secure_filename(f"{id_number}.jpg")
    photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)

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
    salted_token = token + "PoltekSSN"
    hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
    encoded_token = base64.b64encode(hashed_token.encode()).decode()

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
    voter_id = escape(request.form['voter_id'])
    action = escape(request.form['action'])
    with get_db_connection() as conn:
        c = conn.cursor()
        # Mulai transaksi
        conn.execute("BEGIN IMMEDIATE;")
        if action == 'approve':
            c.execute("UPDATE voters SET approved = 1 WHERE id = ?", (voter_id,))
            flash('Voter approved successfully')
        elif action == 'reject':
            c.execute("DELETE FROM voters WHERE id = ?", (voter_id,))
            flash('Voter rejected successfully')
        conn.commit()
    return redirect(url_for('approve_voter_page'))


@app.route('/vote', methods=['GET'])
def vote_page():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, photo, class, type FROM candidates")
    candidates = c.fetchall()
    conn.close()

    # Pisahkan kandidat berdasarkan jenis pemilihan
    senat_candidates = [candidate for candidate in candidates if candidate['type'] == 'senat']
    demus_candidates = [candidate for candidate in candidates if candidate['type'] == 'demus']

    token = request.args.get('token')
    if token:
        # Proses token: tambahkan salt, hash, dan encode
        salted_token = token + "PoltekSSN"
        hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
        encoded_token = base64.b64encode(hashed_token.encode()).decode()

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT token_used_senat, token_used_dewan FROM voters WHERE token = ?", (encoded_token,))
        voter = c.fetchone()
        conn.close()
        if voter:
            token_used_senat, token_used_dewan = voter
            if token_used_senat == 0:
                # Belum vote senat: tampilkan halaman vote untuk senat
                return render_template(
                    'vote.html',
                    candidates=senat_candidates,
                    no_candidates=(len(senat_candidates) == 0),
                    voting_stage='senat',
                    token=token
                )
            elif token_used_dewan == 0:
                # Sudah vote senat tapi belum vote demus: langsung tampilkan halaman vote untuk demus
                return render_template(
                    'vote.html',
                    candidates=demus_candidates,
                    no_candidates=(len(demus_candidates) == 0),
                    voting_stage='demus',
                    token=token
                )
            else:
                # Token sudah digunakan untuk kedua vote
                flash('Token sudah digunakan untuk kedua pemilihan.')
                return redirect(url_for('vote_page'))
    # Jika token tidak ada, default ke halaman vote senat
    return render_template(
        'vote.html',
        candidates=senat_candidates,
        no_candidates=(len(senat_candidates) == 0),
        voting_stage='senat',
        token=token
    )


@app.route('/vote', methods=['POST'])
@limiter.limit("20000000 per minute")
def vote():
    candidate_id = escape(request.form['candidate'])
    token = escape(request.form['token'])
    voting_stage = escape(request.form['voting_stage'])

    salted_token = token + "PoltekSSN"
    hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
    encoded_token = base64.b64encode(hashed_token.encode()).decode()

    with get_db_connection() as conn:
        c = conn.cursor()
        # Mulai transaksi untuk memastikan operasi validasi dan update atomik
        conn.execute("BEGIN IMMEDIATE;")
        c.execute("SELECT id_number, approved, token_used_senat, token_used_dewan FROM voters WHERE token = ?", (encoded_token,))
        voter = c.fetchone()
        if not voter:
            flash('Invalid token')
            return redirect(url_for('vote_page', token=token))
        id_number, approved, token_used_senat, token_used_dewan = voter
        if approved == 0:
            flash('Voter not approved')
            return redirect(url_for('vote_page', token=token))
        if voting_stage == 'senat' and token_used_senat == 1:
            flash('Vote for Ketua Senat has already been cast. Please proceed to vote for Ketua Dewan Musyawarah Taruna.')
            return redirect(url_for('vote_page', token=token))
        if voting_stage == 'demus' and token_used_dewan == 1:
            flash('Vote for Ketua Dewan Musyawarah Taruna has already been cast.')
            return redirect(url_for('vote_page', token=token))
        if token_used_senat == 1 and token_used_dewan == 1:
            flash('Token already used for both votes.')
            return redirect(url_for('vote_page', token=token))

        # Proses blind signature dan simpan ballot
        # Pertama, ambil atau buat kunci RSA
        with get_db_connection() as conn_keys:
            c_keys = conn_keys.cursor()
            c_keys.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
            key = c_keys.fetchone()
        if key:
            n, e, d = int(key[0]), int(key[1]), int(key[2])
            signer = bs.Signer()
            signer.public_key = {'n': n, 'e': e}
            signer.private_key = {'d': d}
        else:
            signer = bs.Signer()
            public_key = signer.get_public_key()
            n = public_key['n']
            e = public_key['e']
            d = signer.private_key['d']
            with get_db_connection() as conn_keys:
                c_keys = conn_keys.cursor()
                c_keys.execute("INSERT INTO keys (n, e, d, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                               (str(n), str(e), str(d)))
                conn_keys.commit()

        # Proses pembuatan ballot (blind signature)
        x = secrets.randbelow(n - 1) + 1
        concat_message = str(candidate_id) + str(x)
        message_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        message_hash_int = int(message_hash, 16)
        voter_obj = bs.Voter(n, "y")
        blind_message = voter_obj.blind_message(message_hash_int, n, e)
        signed_blind_message = signer.sign_message(blind_message, voter_obj.get_eligibility())
        signed_message = voter_obj.unwrap_signature(signed_blind_message, n)

        # Simpan ballot ke database
        c.execute('''INSERT INTO ballots (x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (str(x), concat_message, str(message_hash_int), str(blind_message),
                   str(signed_blind_message), str(signed_message)))

        # Update status token berdasarkan stage voting
        if voting_stage == 'senat':
            c.execute("UPDATE voters SET token_used_senat = 1 WHERE token = ?", (encoded_token,))
            flash('Vote cast successfully for Ketua Senat. Please proceed to vote for Ketua Dewan Musyawarah Taruna.')
        elif voting_stage == 'demus':
            c.execute("UPDATE voters SET token_used_dewan = 1 WHERE token = ?", (encoded_token,))
            flash('Vote cast successfully for Ketua Dewan Musyawarah Taruna. Thank you for voting!')
        conn.commit()
    return redirect(url_for('vote_page', token=token))


@app.route('/recap', methods=['GET'])
@limiter.limit("20000000 per minute")
def recap():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    verified_ballots, vote_counts, candidates = recap_votes()
    return render_template('recap.html', vote_counts=vote_counts, candidates=candidates)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/voter_status', methods=['GET'])
@limiter.limit("20000000 per minute")
def voter_status():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_number, approved, token_used_senat, token_used_dewan FROM voters")
    voters = c.fetchall()
    conn.close()

    return render_template('voter_status.html', voters=voters)


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


@app.route('/get_candidate_photos')
def get_candidate_photos():
    candidates = get_all_candidates()
    # Konversi setiap sqlite3.Row menjadi dictionary
    candidates = [dict(c) for c in candidates]
    photos = {
        c['name']: {
            'photo': url_for('static', filename=c['photo']),
            'type': c.get('candidate_type', '')
        }
        for c in candidates
    }
    return jsonify(photos)


@app.route('/live_count', methods=['GET'])
@limiter.limit("20000000 per minute")
def live_count():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    vote_type = request.args.get('type')  # Dapatkan jenis vote dari parameter URL

    def generate():
        verified_ballots, _, _ = recap_votes()
        for candidate_name, candidate_type in verified_ballots:
            if candidate_type == vote_type:  # Hanya kirim data sesuai pilihan user
                yield f"data: {json.dumps({'candidate': candidate_name, 'type': candidate_type})}\n\n"
                time.sleep(0.2)  # Delay 1 detik

    return Response(generate(), mimetype='text/event-stream')


if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    cert_path = "dev.certificate.crt"
    key_path = "dev.private.key"

    local_ip = get_local_ip()
    print(f"Running Flask app on IP: {local_ip}")

    app.run(host=local_ip, port=5001, ssl_context=(cert_path, key_path))
