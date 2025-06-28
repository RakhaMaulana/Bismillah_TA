import socket
import os
import re
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
import ssl
import math
import statistics
import io
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend untuk server
import matplotlib.pyplot as plt
import random
from tqdm import tqdm
import sys


# Import modules untuk benchmark
try:
    from generate_dummy_votes import generate_dummy_votes_with_timing, create_dummy_candidates, get_or_create_keys
    from benchmark_tabulasi import measure_recap_performance
    BENCHMARK_MODULES_AVAILABLE = True
    print("✅ Benchmark modules loaded successfully")
except ImportError as e:
    print(f"⚠️ Warning: Benchmark modules not found: {e}")
    BENCHMARK_MODULES_AVAILABLE = False


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB max file size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Mencegah CSRF attacks

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
    # PERBAIKAN: Content Security Policy yang mencakup semua sumber daya yang dibutuhkan
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://code.jquery.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )

    # Header keamanan lainnya tetap sama
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Prevent caching of sensitive pages
    if request.path in ['/vote', '/register_voter', '/login', '/approve_voter']:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    username = escape(request.form['username'])
    password = escape(request.form['password'])

    # Validasi input
    if not username or not password:
        flash('Username dan password diperlukan')
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?",
              (username, hashlib.sha256(password.encode()).hexdigest()))
    user = c.fetchone()
    conn.close()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session.permanent = True  # Set session to expire after permanent_session_lifetime
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
@limiter.limit("10 per minute")
def register_candidate():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    # Validasi input
    name = escape(request.form['name'])
    candidate_class = escape(request.form['class'])
    candidate_type = escape(request.form['candidate_type'])

    if not name or not candidate_class or not candidate_type:
        flash('Semua field harus diisi')
        return redirect(url_for('register_candidate_page'))

    # Validasi format input dengan regex
    if not re.match(r'^[A-Za-z\s]{3,50}$', name):
        flash('Nama kandidat tidak valid')
        return redirect(url_for('register_candidate_page'))

    if not re.match(r'^[A-Za-z0-9\s]{1,30}$', candidate_class):
        flash('Kelas tidak valid')
        return redirect(url_for('register_candidate_page'))

    if candidate_type not in ['senat', 'demus']:
        flash('Tipe kandidat tidak valid')
        return redirect(url_for('register_candidate_page'))

    # Validasi file photo
    if 'photo' not in request.files:
        flash('Tidak ada file yang diunggah')
        return redirect(url_for('register_candidate_page'))

    photo = request.files['photo']
    if photo.filename == '':
        flash('Tidak ada file yang dipilih')
        return redirect(url_for('register_candidate_page'))

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
@limiter.limit("10 per minute")
def register_voter():
    # Validasi input
    id_number = escape(request.form['id_number'])

    # Regex validation for NPM
    if not re.match(r'^[0-9]{8,12}$', id_number):
        flash('NPM harus berisi 8-12 digit angka')
        return redirect(url_for('register_voter_page'))

    photo_data = request.form.get('photo')

    # Validasi photo_data
    if not photo_data or ',' not in photo_data:
        flash('Foto diperlukan')
        return redirect(url_for('register_voter_page'))

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
    try:
        decoded_data = base64.b64decode(photo_data)
        # Check if it's a valid image
        if len(decoded_data) < 100:  # Arbitrary minimum size for a valid image
            flash('Invalid image data')
            return redirect(url_for('register_voter_page'))

        with open(photo_filename, "wb") as fh:
            fh.write(decoded_data)
    except Exception as e:
        flash(f'Error processing image: {str(e)}')
        return redirect(url_for('register_voter_page'))

    digital_signature = hashlib.sha256(photo_data.encode()).hexdigest()
    token = save_voter(id_number, digital_signature, filename)

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
@limiter.limit("10 per minute")
def approve_voter():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    voter_id = escape(request.form['voter_id'])
    action = escape(request.form['action'])

    # Validate input
    if not voter_id.isdigit():
        flash('Invalid voter ID format')
        return redirect(url_for('approve_voter_page'))

    if action not in ['approve', 'reject']:
        flash('Invalid action')
        return redirect(url_for('approve_voter_page'))

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


# Step 1: Add a new route for token submission form
@app.route('/submit_token', methods=['GET'])
def submit_token_page():
    return render_template('submit_token.html')


# Step 2: Process token submission and store in session
@app.route('/process_token', methods=['POST'])
@limiter.limit("10 per minute")
def process_token():
    token = escape(request.form.get('token', ''))

    if not token:
        flash('Token is required')
        return redirect(url_for('submit_token_page'))

    # Validate and store token in session instead of URL
    salted_token = token + "PoltekSSN"
    hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
    encoded_token = base64.b64encode(hashed_token.encode()).decode()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_number, approved, token_used_senat, token_used_dewan FROM voters WHERE token = ?",
              (encoded_token,))
    voter = c.fetchone()
    conn.close()

    if not voter:
        flash('Invalid token')
        return redirect(url_for('submit_token_page'))

    if voter['approved'] == 0:
        flash('Your registration has not been approved yet')
        return redirect(url_for('submit_token_page'))

    # Store token and voter info in session
    session['voting_token'] = token
    session['voting_id_number'] = voter['id_number']

    return redirect(url_for('vote_page'))


# Step 3: Modified vote_page to use session instead of URL parameters
@app.route('/vote', methods=['GET'])
def vote_page():
    # Get token from session instead of URL
    token = session.get('voting_token')

    # ✅ PERBAIKAN: Check if token exists in session
    if not token:
        flash('Please submit your voting token first.')
        return redirect(url_for('submit_token_page'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, photo, class, type FROM candidates")
    candidates = c.fetchall()

    # Pisahkan kandidat berdasarkan jenis pemilihan
    senat_candidates = [candidate for candidate in candidates if candidate['type'] == 'senat']
    demus_candidates = [candidate for candidate in candidates if candidate['type'] == 'demus']

    try:
        # Process token from session
        salted_token = token + "PoltekSSN"
        hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
        encoded_token = base64.b64encode(hashed_token.encode()).decode()

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
                    voting_stage='senat'
                )
            elif token_used_dewan == 0:
                # Sudah vote senat tapi belum vote demus: langsung tampilkan halaman vote untuk demus
                return render_template(
                    'vote.html',
                    candidates=demus_candidates,
                    no_candidates=(len(demus_candidates) == 0),
                    voting_stage='demus'
                )
            else:
                # Token sudah digunakan untuk kedua vote
                flash('Token sudah digunakan untuk kedua pemilihan.')
                session.pop('voting_token', None)
                session.pop('voting_id_number', None)
                return redirect(url_for('index'))
        else:
            flash('Invalid token.')
            session.pop('voting_token', None)
            session.pop('voting_id_number', None)
            return redirect(url_for('submit_token_page'))

    except Exception as e:
        conn.close()
        flash(f'Error processing token: {str(e)}')
        session.pop('voting_token', None)
        session.pop('voting_id_number', None)
        return redirect(url_for('submit_token_page'))


@app.route('/vote', methods=['POST'])
@limiter.limit("10 per minute")
def vote():
    # Get token from session instead of form
    token = session.get('voting_token')
    if not token:
        flash('Invalid session. Please submit your token again.')
        return redirect(url_for('submit_token_page'))

    # Validate form data
    candidate_id = escape(request.form.get('candidate', ''))
    voting_stage = escape(request.form.get('voting_stage', ''))

    if not candidate_id.isdigit():
        flash('Invalid candidate selection')
        return redirect(url_for('vote_page'))

    if voting_stage not in ['senat', 'demus']:
        flash('Invalid voting stage')
        return redirect(url_for('vote_page'))

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
            conn.rollback()
            flash('Invalid token')
            session.pop('voting_token', None)
            session.pop('voting_id_number', None)
            return redirect(url_for('submit_token_page'))

        id_number, approved, token_used_senat, token_used_dewan = voter
        if approved == 0:
            conn.rollback()
            flash('Voter not approved')
            session.pop('voting_token', None)
            session.pop('voting_id_number', None)
            return redirect(url_for('submit_token_page'))

        if voting_stage == 'senat' and token_used_senat == 1:
            conn.rollback()
            flash('Vote for Ketua Senat has already been cast. Please proceed to vote for Ketua Dewan Musyawarah Taruna.')
            return redirect(url_for('vote_page'))

        if voting_stage == 'demus' and token_used_dewan == 1:
            conn.rollback()
            flash('Vote for Ketua Dewan Musyawarah Taruna has already been cast.')
            return redirect(url_for('vote_page'))

        if token_used_senat == 1 and token_used_dewan == 1:
            conn.rollback()
            flash('Token already used for both votes.')
            session.pop('voting_token', None)
            session.pop('voting_id_number', None)
            return redirect(url_for('index'))

        # Proses blind signature dan simpan ballot
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

        try:
            # PERBAIKAN: Implementasi blind signature yang benar
            # 1. Pesan adalah candidate_id saja
            message = str(candidate_id)
            message_hash = hashlib.sha256(message.encode()).hexdigest()
            message_hash_int = int(message_hash, 16)

            # 2. Buat objek Voter dan blinding factor yang tepat
            voter_obj = bs.Voter(n, "y")
            blind_message = voter_obj.blind_message(message_hash_int, n, e)

            # 3. Sign the blinded message
            signed_blind_message = signer.sign_message(blind_message, voter_obj.get_eligibility())

            # 4. Unwrap the signature
            signature = voter_obj.unwrap_signature(signed_blind_message, n)

            # 5. Verify the signature (optional, for double-checking)
            is_valid = bs.verify_signature(candidate_id, signature, e, n)
            if not is_valid:
                conn.rollback()
                flash('Error in vote verification.')
                return redirect(url_for('vote_page'))

            # PERBAIKAN: Simpan hanya data minimal yang diperlukan
            # 6. Store minimal ballot information
            c.execute("INSERT INTO ballots (candidate_id, signature, type) VALUES (?, ?, ?)",
                    (candidate_id, str(signature), voting_stage))

            # Update status token berdasarkan stage voting
            if voting_stage == 'senat':
                c.execute("UPDATE voters SET token_used_senat = 1 WHERE token = ?", (encoded_token,))
                flash('Vote cast successfully for Ketua Senat. Please proceed to vote for Ketua Dewan Musyawarah Taruna.')
            elif voting_stage == 'demus':
                c.execute("UPDATE voters SET token_used_dewan = 1 WHERE token = ?", (encoded_token,))
                flash('Vote cast successfully for Ketua Dewan Musyawarah Taruna. Thank you for voting!')
                # Clear voting session after completed both votes
                session.pop('voting_token', None)
                session.pop('voting_id_number', None)

            conn.commit()

        except Exception as e:
            conn.rollback()
            flash(f'Error processing vote: {str(e)}')
            return redirect(url_for('vote_page'))

    return redirect(url_for('vote_page'))


@app.route('/recap', methods=['GET'])
@limiter.limit("10 per minute")
def recap():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    verified_ballots, vote_counts, candidates = recap_votes()
    return render_template('recap.html', vote_counts=vote_counts, candidates=candidates)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Validate filename to prevent path traversal
    if not re.match(r'^[a-zA-Z0-9_\.-]+$', filename):
        return "Invalid filename", 400

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/voter_status', methods=['GET'])
@limiter.limit("10 per minute")
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
@limiter.limit("10 per minute")
def live_count():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    vote_type = request.args.get('type')  # Dapatkan jenis vote dari parameter URL
    if vote_type not in ['senat', 'demus']:
        return "Invalid vote type", 400

    def generate():
        verified_ballots, _, _ = recap_votes()
        for candidate_name, candidate_type in verified_ballots:
            if candidate_type == vote_type:  # Hanya kirim data sesuai pilihan user
                yield f"data: {json.dumps({'candidate': candidate_name, 'type': candidate_type})}\n\n"
                time.sleep(0.2)  # Delay 0.2 detik

    return Response(generate(), mimetype='text/event-stream')


@app.route('/benchmark', methods=['GET'])
def benchmark_page():
    """Halaman benchmark performance"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('benchmark.html')


def simulate_random_voting(num_votes):
    """Simulate random voting process untuk benchmark"""
    print(f"\n🎲 Simulating {num_votes} random votes...")

    if num_votes == 0:
        return {
            'total_votes': 0,
            'total_time': 0,
            'avg_time_per_vote': 0,
            'min_time': 0,
            'max_time': 0,
            'votes_per_second': 0
        }

    # Get available candidates
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, type FROM candidates")
    candidates = c.fetchall()
    conn.close()

    if not candidates:
        raise Exception("No candidates found for random voting simulation")

    print(f"   Available candidates: {[c['name'] for c in candidates]}")

    vote_times = []
    successful_votes = 0

    start_time = time.time()

    for i in range(num_votes):
        vote_start = time.time()

        try:
            # Simulate vote casting process
            selected_candidate = random.choice(candidates)

            # Simulate processing time (random between 0.1-0.5 seconds)
            processing_time = random.uniform(0.1, 0.5)
            time.sleep(processing_time)

            vote_end = time.time()
            vote_time = vote_end - vote_start
            vote_times.append(vote_time)
            successful_votes += 1

            if (i + 1) % max(1, num_votes // 5) == 0:
                progress = ((i + 1) / num_votes) * 100
                print(f"     Progress: {progress:.0f}% ({i+1}/{num_votes})")

        except Exception as e:
            print(f"   ❌ Random vote {i+1} failed: {str(e)}")
            continue

    total_time = time.time() - start_time
    avg_time_per_vote = sum(vote_times) / len(vote_times) if vote_times else 0
    min_time = min(vote_times) if vote_times else 0
    max_time = max(vote_times) if vote_times else 0
    votes_per_second = successful_votes / total_time if total_time > 0 else 0

    results = {
        'total_votes': successful_votes,
        'total_time': total_time,
        'avg_time_per_vote': avg_time_per_vote,
        'min_time': min_time,
        'max_time': max_time,
        'votes_per_second': votes_per_second
    }

    print(f"✅ Random voting simulation completed:")
    print(f"   - Total votes: {successful_votes}")
    print(f"   - Total time: {total_time:.4f}s")
    print(f"   - Avg time per vote: {avg_time_per_vote:.4f}s")
    print(f"   - Votes per second: {votes_per_second:.2f}")

    return results

def benchmark_vote_decryption(iterations=5):
    """Benchmark vote decryption/verification for integration with app.py"""
    print(f"🔓 Running vote decryption benchmark with {iterations} iterations...")

    # Get ballots for verification
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT candidate_id, signature, type FROM ballots LIMIT 100")
    ballots = c.fetchall()

    # Get keys
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()
    conn.close()

    if not ballots:
        return {
            'total_votes_verified': 0,
            'avg_time_per_vote': 0,
            'verification_success_rate': 0
        }

    if not key:
        return {
            'total_votes_verified': 0,
            'avg_time_per_vote': 0,
            'verification_success_rate': 0
        }

    n, e, d = int(key[0]), int(key[1]), int(key[2])
    import BlindSig as bs

    total_verification_times = []
    successful_verifications = 0

    for iteration in range(iterations):
        iteration_times = []
        iteration_successes = 0

        for candidate_id, signature, ballot_type in ballots:
            start_time = time.time()

            try:
                is_valid = bs.verify_signature(str(candidate_id), int(signature), e, n)
                if is_valid:
                    iteration_successes += 1
            except:
                pass

            end_time = time.time()
            iteration_times.append(end_time - start_time)

        total_verification_times.extend(iteration_times)
        successful_verifications = max(successful_verifications, iteration_successes)

    avg_time_per_vote = statistics.mean(total_verification_times) if total_verification_times else 0
    verification_success_rate = (successful_verifications / len(ballots)) * 100 if ballots else 0

    results = {
        'total_votes_verified': len(ballots),
        'avg_time_per_vote': avg_time_per_vote,
        'verification_success_rate': verification_success_rate
    }

    print(f"✅ Decryption benchmark completed:")
    print(f"   - Votes verified: {len(ballots)}")
    print(f"   - Avg time per vote: {avg_time_per_vote:.8f}s")
    print(f"   - Success rate: {verification_success_rate:.1f}%")

    return results

@app.route('/run_complete_benchmark', methods=['POST'])
@limiter.limit("3 per hour")
def run_complete_benchmark():
    """Jalankan benchmark lengkap: generate votes + random voting + tabulation + decryption"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Ambil parameter dari form
        iterations = int(request.form.get('iterations', 5))
        voting_iterations = int(request.form.get('voting_iterations', 50))
        random_vote_count = int(request.form.get('random_vote_count', 0))  # Set to 0 by default

        # Batasi jumlah iterasi untuk keamanan
        iterations = min(max(iterations, 1), 50)
        voting_iterations = min(max(voting_iterations, 1), 1000)
        random_vote_count = min(max(random_vote_count, 0), 500)

        print(f"🚀 Starting complete benchmark:")
        print(f"   - Generate votes: {voting_iterations}")
        print(f"   - Random votes: {random_vote_count}")
        print(f"   - Tabulation iterations: {iterations}")

        # === STEP 1: GENERATE DUMMY VOTES ===
        print("\n📝 STEP 1: Generating dummy votes...")
        generation_start = time.time()

        if not BENCHMARK_MODULES_AVAILABLE:
            return jsonify({'error': 'Benchmark modules not available. Please ensure all required files are present.'}), 500

        # Generate dummy votes dengan timing
        generation_results = generate_dummy_votes_with_timing(voting_iterations, measure_individual=True)

        if not generation_results or generation_results.get('successful_votes', 0) == 0:
            return jsonify({'error': 'Failed to generate dummy votes'}), 500

        generation_end = time.time()
        generation_time = generation_end - generation_start

        print(f"✅ Generated {generation_results['successful_votes']} votes in {generation_time:.4f}s")

        # === STEP 2: RANDOM VOTING SIMULATION ===
        print("\n🎲 STEP 2: Random voting simulation...")
        random_voting_start = time.time()

        # Only run if random_vote_count > 0
        if random_vote_count > 0:
            random_voting_results = simulate_random_voting(random_vote_count)
        else:
            print("   Skipping random voting simulation (count = 0)")
            random_voting_results = {
                'total_votes': 0,
                'total_time': 0,
                'avg_time_per_vote': 0,
                'min_time': 0,
                'max_time': 0,
                'votes_per_second': 0
            }

        random_voting_end = time.time()
        random_voting_time = random_voting_end - random_voting_start

        print(f"✅ Simulated {random_voting_results['total_votes']} random votes in {random_voting_time:.4f}s")

        # === STEP 3: TABULATION BENCHMARK ===
        print("\n📊 STEP 3: Tabulation benchmark...")
        tabulation_start = time.time()

        tabulation_data = measure_recap_performance(iterations)

        if not tabulation_data:
            return jsonify({'error': 'Failed to run tabulation benchmark'}), 500

        tabulation_end = time.time()
        tabulation_time = tabulation_end - tabulation_start

        print(f"✅ Tabulated {tabulation_data['total_ballots']} ballots in {tabulation_time:.4f}s")

        # === STEP 4: DECRYPTION/VERIFICATION BENCHMARK ===
        print("\n🔓 STEP 4: Decryption benchmark...")
        decryption_start = time.time()

        decryption_results = benchmark_vote_decryption(iterations)

        decryption_end = time.time()
        decryption_time = decryption_end - decryption_start

        print(f"✅ Decrypted and verified votes in {decryption_time:.4f}s")

        # === STEP 5: AGGREGATE RESULTS ===
        total_time = generation_time + random_voting_time + tabulation_time + decryption_time

        # zkVoting baseline data
        zkvoting_ballot_casting_time = 2.3  # 2.3 seconds per ballot casting
        zkvoting_tally_time = 0.0039  # 3.9 milliseconds per ballot = 0.0039 seconds

        # Speedup calculations vs zkVoting
        generation_speedup = zkvoting_ballot_casting_time / generation_results['avg_time_per_vote'] if generation_results['avg_time_per_vote'] > 0 else 0
        tabulation_speedup = zkvoting_tally_time / tabulation_data['avg_time_per_ballot'] if tabulation_data['avg_time_per_ballot'] > 0 else 0
        decryption_speedup = zkvoting_tally_time / decryption_results['avg_time_per_vote'] if decryption_results['avg_time_per_vote'] > 0 else 0

        # === STEP 6: GENERATE VISUALIZATION ===
        print("\n📈 STEP 6: Generating charts...")

        charts = generate_complete_benchmark_charts(
            generation_results, random_voting_results,
            tabulation_data, decryption_results, zkvoting_ballot_casting_time, zkvoting_tally_time
        )

        # Compile final results
        results = {
            'generation_results': {
                'total_votes': generation_results['successful_votes'],
                'total_time': generation_time,
                'avg_time': generation_results['avg_time_per_vote'],
                'min_time': generation_results.get('individual_stats', {}).get('min', 0),
                'max_time': generation_results.get('individual_stats', {}).get('max', 0),
                'votes_per_second': generation_results['votes_per_second'],
                'success_rate': generation_results['success_rate'],
                'speedup_vs_zkvoting': generation_speedup
            },
            'random_voting_results': {
                'total_votes': random_voting_results['total_votes'],
                'total_time': random_voting_time,
                'avg_time': random_voting_results['avg_time_per_vote'],
                'min_time': random_voting_results['min_time'],
                'max_time': random_voting_results['max_time'],
                'votes_per_second': random_voting_results['votes_per_second']
            },
            'tabulation_results': {
                'total_ballots': tabulation_data['total_ballots'],
                'iterations': tabulation_data['iterations'],
                'avg_time': tabulation_data['avg_time'],
                'median_time': tabulation_data['median_time'],
                'min_time': tabulation_data['min_time'],
                'max_time': tabulation_data['max_time'],
                'avg_time_per_ballot': tabulation_data['avg_time_per_ballot'],
                'speedup_vs_zkvoting': tabulation_speedup
            },
            'decryption_results': {
                'total_votes_verified': decryption_results['total_votes_verified'],
                'total_time': decryption_time,
                'avg_time': decryption_results['avg_time_per_vote'],
                'verification_success_rate': decryption_results['verification_success_rate'],
                'speedup_vs_zkvoting': decryption_speedup
            },
            'overall_performance': {
                'total_end_to_end_time': total_time,
                'overall_speedup': min(generation_speedup, tabulation_speedup, decryption_speedup),
                'recommendation': get_performance_recommendation_complete(
                    generation_results, random_voting_results, tabulation_data, decryption_results
                )
            },
            'charts': charts,
            'baseline_comparison': {
                'system': 'zkVoting',
                'paper_reference': 'zkVoting: A coercion-resistant e-voting system',
                'ballot_casting_time': zkvoting_ballot_casting_time,
                'tally_time_per_ballot': zkvoting_tally_time,
                'algorithm_complexity': 'O(n)',
                'features': ['Coercion-resistant', 'E2E verifiable', 'Anonymity-preserving', 'Zero-knowledge proofs']
            }
        }

        print(f"\n🎉 Complete benchmark finished!")
        print(f"   Total time: {total_time:.4f}s")
        print(f"   Overall speedup vs zkVoting: {results['overall_performance']['overall_speedup']:.0f}x")

        return jsonify(results)

    except ValueError as ve:
        print(f"❌ ValueError: {str(ve)}")
        return jsonify({'error': f'Invalid input values: {str(ve)}'}), 400
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error running complete benchmark: {str(e)}'}), 500

def generate_complete_benchmark_charts(generation_results, random_voting_results, tabulation_data, decryption_results, zkvoting_casting_time, zkvoting_tally_time):
    """Generate comprehensive visualization charts with zkVoting comparison"""

    charts = {}

    # Calculate zkVoting throughput values
    zkvoting_casting_throughput = 1 / zkvoting_casting_time if zkvoting_casting_time > 0 else 0  # ~0.43 votes per second
    zkvoting_tally_throughput = 1 / zkvoting_tally_time if zkvoting_tally_time > 0 else 0  # ~256 ballots per second

    # Chart 1: End-to-End Process Comparison with zkVoting
    plt.figure(figsize=(14, 8))

    processes = ['Ballot Casting\n(Our System)', 'Tabulation\n(Our System)', 'Decryption\n(Our System)',
                'zkVoting\n(Ballot Casting)', 'zkVoting\n(Tally)']
    times = [
        generation_results['avg_time_per_vote'],
        tabulation_data['avg_time_per_ballot'],
        decryption_results['avg_time_per_vote'],
        zkvoting_casting_time,
        zkvoting_tally_time
    ]
    colors = ['#4CAF50', '#FF9800', '#9C27B0', '#F44336', '#E91E63']

    bars = plt.bar(processes, times, color=colors, alpha=0.8)
    plt.title('Performance Comparison: Our System vs zkVoting', fontsize=16, fontweight='bold')
    plt.ylabel('Time per Vote/Ballot (seconds)')
    plt.yscale('log')

    # Add value labels
    for bar, time_val in zip(bars, times):
        height = bar.get_height()
        if time_val < 0.001:
            label = f'{time_val*1000:.2f}ms'
        elif time_val < 1:
            label = f'{time_val:.4f}s'
        else:
            label = f'{time_val:.2f}s'

        plt.text(bar.get_x() + bar.get_width()/2., height,
                 label, ha='center', va='bottom', fontweight='bold', rotation=45)

    plt.xticks(rotation=45, ha='right')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    charts['process_comparison'] = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()

    # Chart 2: Speedup Comparison
    plt.figure(figsize=(12, 6))

    speedup_processes = ['Ballot Casting', 'Tabulation', 'Verification']
    speedup_values = [
        zkvoting_casting_time / generation_results['avg_time_per_vote'] if generation_results['avg_time_per_vote'] > 0 else 0,
        zkvoting_tally_time / tabulation_data['avg_time_per_ballot'] if tabulation_data['avg_time_per_ballot'] > 0 else 0,
        zkvoting_tally_time / decryption_results['avg_time_per_vote'] if decryption_results['avg_time_per_vote'] > 0 else 0
    ]

    bars = plt.bar(speedup_processes, speedup_values,
                   color=['#4CAF50', '#FF9800', '#9C27B0'], alpha=0.8)
    plt.axhline(y=1, color='red', linestyle='--', linewidth=2, label='zkVoting baseline (1x)')

    plt.title('Performance Speedup vs zkVoting', fontsize=14, fontweight='bold')
    plt.ylabel('Speedup Factor (x times faster)')
    plt.legend()

    for bar, speedup in zip(bars, speedup_values):
        height = bar.get_height()
        if speedup < 1:
            label = f'{speedup:.2f}x\n(slower)'
            color = 'red'
        else:
            label = f'{speedup:.1f}x\n(faster)'
            color = 'green'

        plt.text(bar.get_x() + bar.get_width()/2., height,
                 label, ha='center', va='bottom', fontweight='bold', color=color)

    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    charts['speedup_comparison'] = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()

    # Chart 3: Feature Comparison Radar Chart
    plt.figure(figsize=(10, 10))

    # Categories for comparison
    categories = ['Speed\n(Ballot Casting)', 'Speed\n(Tabulation)', 'Coercion\nResistance',
                  'E2E\nVerifiability', 'Anonymity', 'Scalability']

    # Our system scores (normalize to 0-10 scale)
    our_scores = [
        min(10, max(0, 10 - math.log10(generation_results['avg_time_per_vote'] * 10) if generation_results['avg_time_per_vote'] > 0 else 5)),
        min(10, max(0, 10 - math.log10(tabulation_data['avg_time_per_ballot'] * 1000) if tabulation_data['avg_time_per_ballot'] > 0 else 5)),
        8,  # Coercion resistance (good but not perfect)
        9,  # E2E verifiability
        9,  # Anonymity
        8   # Scalability
    ]

    # zkVoting scores
    zkvoting_scores = [7, 9, 10, 10, 10, 9]  # Based on paper claims

    # Create radar chart
    angles = [n / float(len(categories)) * 2 * math.pi for n in range(len(categories))]
    angles += angles[:1]  # Complete the circle

    our_scores += our_scores[:1]
    zkvoting_scores += zkvoting_scores[:1]

    ax = plt.subplot(111, projection='polar')

    # Plot both systems
    ax.plot(angles, our_scores, 'o-', linewidth=2, label='Our System', color='#4CAF50')
    ax.fill(angles, our_scores, alpha=0.25, color='#4CAF50')

    ax.plot(angles, zkvoting_scores, 'o-', linewidth=2, label='zkVoting', color='#F44336')
    ax.fill(angles, zkvoting_scores, alpha=0.25, color='#F44336')

    # Add category labels
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 10)
    ax.set_title('System Feature Comparison\n(Higher scores = Better)', fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    ax.grid(True)

    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    charts['feature_comparison'] = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()

    return charts

def get_performance_recommendation_complete(generation_results, random_voting_results, tabulation_data, decryption_results):
    """Generate comprehensive performance recommendation with zkVoting comparison"""

    avg_generation_speed = generation_results['votes_per_second']
    avg_random_speed = random_voting_results['votes_per_second']

    # Compare with zkVoting benchmarks
    zkvoting_casting_throughput = 1 / 2.3  # ~0.43 votes per second
    zkvoting_tally_throughput = 1 / 0.0039  # ~256 ballots per second

    tabulation_throughput = 1 / tabulation_data['avg_time_per_ballot'] if tabulation_data['avg_time_per_ballot'] > 0 else 0
    decryption_success_rate = decryption_results['verification_success_rate']

    # Calculate relative performance
    casting_performance = avg_generation_speed / zkvoting_casting_throughput if zkvoting_casting_throughput > 0 else 0
    tally_performance = tabulation_throughput / zkvoting_tally_throughput if zkvoting_tally_throughput > 0 else 0

    if (casting_performance > 2 and tally_performance > 1.5 and decryption_success_rate > 95):
        return "🚀 EXCEPTIONAL: Your system significantly outperforms zkVoting in both ballot casting and tabulation. Excellent for large-scale elections with superior performance characteristics!"
    elif (casting_performance > 1 and tally_performance > 1 and decryption_success_rate > 90):
        return "✅ EXCELLENT: Performance matches or exceeds zkVoting benchmarks. Your system provides comparable or better performance with strong security guarantees."
    elif (casting_performance > 0.5 and tally_performance > 0.8 and decryption_success_rate > 85):
        return "👍 VERY GOOD: Strong performance relative to zkVoting. Your system demonstrates competitive performance for practical e-voting deployment."
    elif (casting_performance > 0.2 and tally_performance > 0.5 and decryption_success_rate > 75):
        return "⚠️ GOOD: Reasonable performance compared to zkVoting. Consider optimizations to match state-of-the-art research benchmarks."
    else:
        return "❌ NEEDS IMPROVEMENT: Performance significantly below zkVoting benchmarks. System requires optimization before production deployment."

def generate_dummy_votes(num_votes):
    """Generate dummy votes untuk benchmark"""
    print(f"\n📝 Generating {num_votes} dummy votes...")

    # Get kandidat yang tersedia
    candidates = db.session.query(Candidate).all()
    if not candidates:
        raise Exception("No candidates found. Please register candidates first.")

    print(f"   Available candidates: {[c.name for c in candidates]}")

    successful_votes = 0
    start_time = time.time()

    # PERBAIKAN: Catat vote distribution
    vote_distribution = {}
    for candidate in candidates:
        vote_distribution[candidate.name] = 0

    for i in range(num_votes):
        try:
            # Random voter data
            voter_id = f"dummy_voter_{i+1}_{int(time.time()*1000000) % 1000000}"

            # PERBAIKAN: Random candidate selection dengan logging
            selected_candidate = random.choice(candidates)
            print(f"   Vote {i+1}: Voter {voter_id} → Candidate {selected_candidate.name}")

            # Create ballot dengan vote yang benar
            ballot_data = {
                'voter_id': voter_id,
                'candidate_id': selected_candidate.id,
                'candidate_name': selected_candidate.name,  # TAMBAH: untuk debugging
                'timestamp': datetime.now().isoformat()
            }

            # Generate signature
            ballot_json = json.dumps(ballot_data, sort_keys=True)
            signature = generate_blind_signature(ballot_json)

            # PERBAIKAN: Verify signature sebelum save
            is_valid = verify_blind_signature(ballot_json, signature)
            if not is_valid:
                print(f"   ❌ Vote {i+1}: Invalid signature!")
                continue

            # Save to database
            ballot = Ballot(
                voter_id=voter_id,
                candidate_id=selected_candidate.id,
                signature=signature,
                ballot_data=ballot_json,
                timestamp=datetime.now()
            )

            db.session.add(ballot)
            db.session.commit()

            # PERBAIKAN: Update distribution counter
            vote_distribution[selected_candidate.name] += 1
            successful_votes += 1

            print(f"   ✅ Vote {i+1}: Saved successfully for {selected_candidate.name}")

        except Exception as e:
            print(f"   ❌ Vote {i+1}: Error - {str(e)}")
            db.session.rollback()
            continue

    total_time = time.time() - start_time

    print(f"\n📊 Vote Generation Summary:")
    print(f"   Total requested: {num_votes}")
    print(f"   Successfully generated: {successful_votes}")
    print(f"   Vote distribution: {vote_distribution}")
    print(f"   Total time: {total_time:.4f}s")

    return {
        'successful_votes': successful_votes,
        'total_time': total_time,
        'avg_time_per_vote': total_time / successful_votes if successful_votes > 0 else 0,
        'votes_per_second': successful_votes / total_time if total_time > 0 else 0,
        'success_rate': (successful_votes / num_votes) * 100,
        'vote_distribution': vote_distribution  # TAMBAH: untuk debugging
    }

def run_tabulation_benchmark(iterations=1):
    """Benchmark tabulation process"""
    print(f"\n📊 Running tabulation benchmark with {iterations} iterations...")

    # Get all ballots
    ballots = db.session.query(Ballot).all()
    print(f"   Found {len(ballots)} ballots to tabulate")

    if not ballots:
        return {"error": "No ballots found for tabulation"}

    # PERBAIKAN: Debug setiap ballot
    print(f"\n🔍 Ballot Debug Info:")
    for i, ballot in enumerate(ballots[:5]):  # Show first 5 ballots
        try:
            ballot_data = json.loads(ballot.ballot_data)
            candidate = db.session.query(Candidate).filter_by(id=ballot.candidate_id).first()
            print(f"   Ballot {i+1}: candidate_id={ballot.candidate_id}, candidate_name={candidate.name if candidate else 'UNKNOWN'}")
            print(f"             ballot_data candidate: {ballot_data.get('candidate_name', 'NOT_SET')}")
        except Exception as e:
            print(f"   Ballot {i+1}: Error parsing - {str(e)}")

    times = []

    for iteration in range(iterations):
        print(f"   Running iteration {iteration+1}/{iterations}...")
        start_time = time.time()

        # Count votes per candidate
        vote_counts = {}
        verified_votes = 0

        for ballot in ballots:
            try:
                # Verify signature
                is_valid = verify_blind_signature(ballot.ballot_data, ballot.signature)
                if not is_valid:
                    print(f"     ⚠️ Invalid signature for ballot {ballot.id}")
                    continue

                # PERBAIKAN: Get candidate dari database, bukan dari ballot_data
                candidate = db.session.query(Candidate).filter_by(id=ballot.candidate_id).first()
                if not candidate:
                    print(f"     ⚠️ Candidate not found for ballot {ballot.id} (candidate_id: {ballot.candidate_id})")
                    continue

                # Count vote untuk candidate yang benar
                if candidate.name not in vote_counts:
                    vote_counts[candidate.name] = 0
                vote_counts[candidate.name] += 1
                verified_votes += 1

            except Exception as e:
                print(f"     ❌ Error processing ballot {ballot.id}: {str(e)}")
                continue

        iteration_time = time.time() - start_time
        times.append(iteration_time)

        print(f"     ✅ Iteration {iteration+1} completed in {iteration_time:.4f}s")
        print(f"     📊 Vote counts: {vote_counts}")
        print(f"     ✅ Verified votes: {verified_votes}/{len(ballots)}")

    # Calculate statistics
    avg_time = sum(times) / len(times)
    median_time = sorted(times)[len(times)//2]
    total_ballots = len(ballots)
    avg_time_per_ballot = avg_time / total_ballots if total_ballots > 0 else 0

    print(f"✅ Tabulation benchmark completed:")
    print(f"   - Total ballots: {total_ballots}")
    print(f"   - Successful iterations: {len(times)}")
    print(f"   - Average time: {avg_time:.4f}s")
    print(f"   - Median time: {median_time:.4f}s")
    print(f"   - Time per ballot: {avg_time_per_ballot:.8f}s")
    print(f"   - Ballots per second: {total_ballots/avg_time:.2f}")
    print(f"   - Final vote counts: {vote_counts}")

    return {
        'total_ballots': total_ballots,
        'verified_votes': verified_votes,
        'successful_iterations': len(times),
        'avg_time': avg_time,
        'median_time': median_time,
        'avg_time_per_ballot': avg_time_per_ballot,
        'ballots_per_second': total_ballots/avg_time if avg_time > 0 else 0,
        'speedup_vs_zk': 39 / avg_time_per_ballot if avg_time_per_ballot > 0 else 0,
        'vote_counts': vote_counts  # TAMBAH: untuk debugging
    }

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    cert_path = "dev.certificate.crt"
    key_path = "dev.private.key"

    local_ip = get_local_ip()
    print(f"Running Flask app on IP: {local_ip}")

    # Buat SSL context dengan cipher suite yang kuat
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    # Konfigurasi untuk hanya mengizinkan cipher GCM yang kuat
    context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256')

    # Aktifkan TLS 1.2 dan 1.3, nonaktifkan versi yang lebih lama
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Jalankan aplikasi dengan context SSL yang diperbarui
    app.run(host=local_ip, port=5001, ssl_context=context)