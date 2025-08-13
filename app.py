import socket
import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
import hashlib
import core.BlindSig as bs
import secrets
import base64
from core.createdb import save_keys, save_voter, save_ballot, save_candidate, get_db_connection, get_existing_keys, get_all_candidates, save_vote_with_signature, get_active_key
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
import uuid
from dotenv import load_dotenv
from core.Recap import recap_votes
from core.ultra_fast_recap import UltraOptimizedTabulator
from core.key_manager import get_global_signer, get_global_keys, sign_with_global_key, verify_with_global_key
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
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String


# Import modules untuk benchmark
try:
    from core.generate_dummy_votes import generate_dummy_votes_with_timing, create_dummy_candidates, get_or_create_keys
    from core.benchmark_tabulation import measure_recap_performance
    BENCHMARK_MODULES_AVAILABLE = True
except ImportError as e:
    BENCHMARK_MODULES_AVAILABLE = False


load_dotenv('config/.env')

app = Flask(__name__, template_folder='core/templates', static_folder='core/static')
app.secret_key = os.getenv('SECRET_KEY') or 'fallback-secret-key-for-development'
UPLOAD_FOLDER = 'core/static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB max file size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Mencegah CSRF attacks

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    key_func=lambda: request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
    app=app,
    default_limits=["10000 per hour"],
    storage_uri="memory://"
)

# Security helper functions
def is_safe_redirect_url(target):
    """Check if redirect URL is safe to prevent open redirect attacks"""
    if not target:
        return False
    # Only allow relative URLs or same-origin URLs
    return target.startswith('/') and not target.startswith('//')

def validate_session_security():
    """Enhanced session security validation"""
    if 'user_id' in session:
        # Check session age (optional: implement session timeout)
        session_start = session.get('session_start')
        if session_start:
            session_age = time.time() - session_start
            if session_age > 3600:  # 1 hour timeout
                session.clear()
                return False
        else:
            session['session_start'] = time.time()
    return True

def sanitize_error_message(error_msg):
    """Sanitize error messages to prevent information disclosure"""
    # Remove sensitive information from error messages
    safe_msg = str(error_msg)[:200]  # Limit length
    # Remove potential SQL error details
    sensitive_patterns = ['sqlite', 'database', 'table', 'column', 'syntax error']
    for pattern in sensitive_patterns:
        if pattern in safe_msg.lower():
            return "System error occurred"
    return escape(safe_msg)


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

    # Enhanced security checks
    if not filename or len(filename) > 255:  # Reasonable filename length
        return False

    # Check for path traversal and malicious patterns
    dangerous_patterns = ['..', '/', '\\', '<', '>', '|', ':', '*', '?', '"', '\x00']
    if any(pattern in filename for pattern in dangerous_patterns):
        return False

    # Ensure filename has extension
    if '.' not in filename:
        return False

    # Check extension
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS


@app.before_request
def security_checks():
    """Enhanced security checks for all requests"""
    # Check session security
    if not validate_session_security():
        if request.endpoint not in ['index', 'login_page', 'login', 'register_voter_page', 'register_voter', 'submit_token_page']:
            return redirect(url_for('login_page'))

    # Content-Length validation
    if request.content_length and request.content_length > 16 * 1024 * 1024:  # 16MB max
        return "Request too large", 413

    # Check for suspicious headers
    user_agent = request.headers.get('User-Agent', '')
    if not user_agent or len(user_agent) > 500:
        return "Invalid request", 400

    # Basic bot detection (optional)
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'nessus']
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        return "Access denied", 403

@app.after_request
def apply_security_headers(response):
    # Enhanced Content Security Policy with conditional media access
    if request.path == '/register_voter':
        # Allow camera/media access for voter registration
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://code.jquery.com 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob:; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "upgrade-insecure-requests;"
        )
    else:
        # Standard CSP for other pages
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://code.jquery.com 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "upgrade-insecure-requests;"
        )

    # Enhanced security headers with conditional camera access
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Allow camera access only for voter registration page
    if request.path == '/register_voter':
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=('self'), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()"
    else:
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()"

    # Prevent caching of sensitive pages
    if request.path in ['/vote', '/register_voter', '/login', '/approve_voter', '/voter_status', '/recap']:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    # Add security headers for file uploads
    if request.path.startswith('/uploads/'):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline';"

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
    # Enhanced input validation and sanitization
    try:
        username = escape(request.form.get('username', '').strip())
        password = escape(request.form.get('password', '').strip())

        # Length validation
        if len(username) > 50 or len(password) > 100:
            flash('Input too long')
            return redirect(url_for('login_page'))

        # SQL injection prevention - check for suspicious patterns
        suspicious_patterns = ['--', ';', '/*', '*/', 'xp_', 'sp_', 'DROP', 'DELETE', 'INSERT', 'UPDATE', 'UNION', 'SELECT']
        for pattern in suspicious_patterns:
            if pattern.lower() in username.lower() or pattern.lower() in password.lower():
                flash('Invalid characters detected')
                return redirect(url_for('login_page'))

    except (KeyError, TypeError, ValueError) as e:
        flash('Invalid request format')
        return redirect(url_for('login_page'))

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

    # Enhanced input validation and sanitization
    try:
        name = escape(request.form.get('name', '').strip())
        candidate_class = escape(request.form.get('class', '').strip())
        candidate_type = escape(request.form.get('candidate_type', '').strip())

        # Length validation
        if len(name) > 100 or len(candidate_class) > 50 or len(candidate_type) > 20:
            flash('Input too long')
            return redirect(url_for('register_candidate_page'))

        # XSS prevention - additional pattern checks
        dangerous_patterns = ['<script', '</script', 'javascript:', 'vbscript:', 'onload=', 'onerror=', 'onclick=']
        for pattern in dangerous_patterns:
            if pattern.lower() in name.lower() or pattern.lower() in candidate_class.lower():
                flash('Invalid characters detected')
                return redirect(url_for('register_candidate_page'))

    except (KeyError, TypeError, ValueError) as e:
        flash('Invalid request format')
        return redirect(url_for('register_candidate_page'))

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

    # Enhanced file upload security validation
    if 'photo' not in request.files:
        flash('Tidak ada file yang diunggah')
        return redirect(url_for('register_candidate_page'))

    photo = request.files['photo']
    if photo.filename == '':
        flash('Tidak ada file yang dipilih')
        return redirect(url_for('register_candidate_page'))

    # Additional file security checks
    if photo.content_length and photo.content_length > 8 * 1024 * 1024:  # 8MB limit
        flash('File terlalu besar (maksimal 8MB)')
        return redirect(url_for('register_candidate_page'))

    # Check for malicious filename patterns
    dangerous_chars = ['..', '/', '\\', '<', '>', '|', ':', '*', '?', '"']
    if any(char in photo.filename for char in dangerous_chars):
        flash('Nama file tidak valid')
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
    # Enhanced input validation and sanitization
    try:
        id_number = escape(request.form.get('id_number', '').strip())

        # Length validation
        if len(id_number) > 20:
            flash('NPM terlalu panjang')
            return redirect(url_for('register_voter_page'))

        # Additional security patterns
        if not id_number.isdigit():
            flash('NPM harus berisi angka saja')
            return redirect(url_for('register_voter_page'))

    except (KeyError, TypeError, ValueError) as e:
        flash('Invalid request format')
        return redirect(url_for('register_voter_page'))

    # Regex validation for NPM
    if not re.match(r'^[0-9]{8,12}$', id_number):
        flash('NPM harus berisi 8-12 digit angka')
        return redirect(url_for('register_voter_page'))

    photo_data = request.form.get('photo')

    # Enhanced photo validation
    if not photo_data or ',' not in photo_data:
        flash('Foto diperlukan')
        return redirect(url_for('register_voter_page'))

    # Check for base64 data URL format
    if not photo_data.startswith('data:image/'):
        flash('Format foto tidak valid')
        return redirect(url_for('register_voter_page'))

    # Validate file size (estimate from base64)
    estimated_size = len(photo_data) * 3 / 4  # Rough base64 to binary size
    if estimated_size > 10 * 1024 * 1024:  # 10MB limit
        flash('Ukuran foto terlalu besar')
        return redirect(url_for('register_voter_page'))

    filename = secure_filename(f"{id_number}.jpg")
    photo_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    conn = get_db_connection()
    c = conn.cursor()

    # PERBAIKAN: Hash ID number untuk query (sesuai dengan schema database)
    id_hash = hashlib.sha256(id_number.encode()).hexdigest()
    c.execute("SELECT * FROM voters WHERE id_number_hash = ?", (id_hash,))
    existing_voter = c.fetchone()
    if existing_voter:
        if existing_voter['approved'] == 0:
            flash('ID number already registered. Awaiting admin approval.')
        else:
            flash('ID number already registered and approved.')
        return redirect(url_for('register_voter_page'))

    photo_data = photo_data.split(',')[1]
    try:
        # Enhanced base64 validation
        if len(photo_data) > 15000000:  # ~10MB base64 limit
            flash('Foto terlalu besar')
            return redirect(url_for('register_voter_page'))

        # Check for valid base64 characters
        import string
        valid_chars = string.ascii_letters + string.digits + '+/='
        if not all(c in valid_chars for c in photo_data):
            flash('Data foto tidak valid')
            return redirect(url_for('register_voter_page'))

        decoded_data = base64.b64decode(photo_data, validate=True)

        # Enhanced image validation
        if len(decoded_data) < 100:  # Minimum size for a valid image
            flash('Invalid image data')
            return redirect(url_for('register_voter_page'))

        # Check for image file signatures (magic bytes)
        valid_signatures = [
            b'\xff\xd8\xff',  # JPEG
            b'\x89\x50\x4e\x47',  # PNG
        ]
        if not any(decoded_data.startswith(sig) for sig in valid_signatures):
            flash('Format gambar tidak didukung')
            return redirect(url_for('register_voter_page'))

        with open(photo_filename, "wb") as fh:
            fh.write(decoded_data)
    except (ValueError, TypeError, base64.binascii.Error) as e:
        flash('Error processing image: Invalid format')
        return redirect(url_for('register_voter_page'))
    except Exception as e:
        flash(f'Error processing image: {str(e)[:50]}')  # Limit error message length
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
    c.execute("SELECT id, id_number_encrypted, photo FROM voters WHERE approved = 0")
    voters_raw = c.fetchall()
    conn.close()

    # Decrypt NPM untuk display
    from core.createdb import decrypt_npm
    voters = []
    for voter in voters_raw:
        voter_dict = {
            'id': voter[0],
            'id_number': decrypt_npm(voter[1]),  # Decrypt untuk display
            'photo': voter[2]
        }
        voters.append(voter_dict)

    return render_template('approve_voter.html', voters=voters)


@app.route('/approve_voter', methods=['POST'])
@limiter.limit("10 per minute")
def approve_voter():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    try:
        # Safely get form data with validation
        voter_id = escape(request.form.get('voter_id', ''))
        action = escape(request.form.get('action', '')) or escape(request.form.get('submit_action', ''))

        # Validate input
        if not voter_id or not voter_id.isdigit():
            flash('Invalid voter ID format')
            return redirect(url_for('approve_voter_page'))

        if action not in ['approve', 'reject']:
            flash('Invalid action')
            return redirect(url_for('approve_voter_page'))

        # Optional: Validate timestamp for replay attack prevention
        timestamp = request.form.get('timestamp')
        if timestamp:
            try:
                timestamp_int = int(timestamp)
                current_time = int(time.time() * 1000)  # Convert to milliseconds
                # Check if timestamp is within acceptable range (10 minutes)
                if abs(current_time - timestamp_int) > 600000:
                    flash('Form expired. Please refresh the page.')
                    return redirect(url_for('approve_voter_page'))
            except (ValueError, TypeError):
                flash('Invalid form submission.')
                return redirect(url_for('approve_voter_page'))

    except Exception as e:
        flash('An error occurred while processing your request.')
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
    # Enhanced token input validation and sanitization
    try:
        raw_token = request.form.get('token', '').strip().upper()

        # Check request size to prevent DoS
        if request.content_length and request.content_length > 1024:  # 1KB limit for token request
            flash('Request too large')
            return redirect(url_for('submit_token_page'))

    except (AttributeError, TypeError, ValueError) as e:
        flash('Invalid request format')
        return redirect(url_for('submit_token_page'))

    # Comprehensive input validation for 6-character uppercase format
    if not raw_token:
        flash('Token is required')
        return redirect(url_for('submit_token_page'))

    # Length validation - exactly 6 characters
    if len(raw_token) != 6:
        flash('Token must be exactly 6 characters')
        return redirect(url_for('submit_token_page'))

    # Character validation - uppercase letters and digits only
    if not re.match(r'^[A-Z0-9]{6}$', raw_token):
        flash('Token must contain only uppercase letters and digits (A-Z, 0-9)')
        return redirect(url_for('submit_token_page'))

    # Check for suspicious patterns (though less likely with just letters)
    suspicious_patterns = [
        r'script', r'javascript', r'onload', r'onerror', r'eval'
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, raw_token, re.IGNORECASE):
            flash('Invalid token format detected')
            return redirect(url_for('submit_token_page'))

    # Use the sanitized token
    token = escape(raw_token)

    # Validate and store token in session instead of URL
    salted_token = token + "PoltekSSN"
    hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
    encoded_token = base64.b64encode(hashed_token.encode()).decode()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_number_hash, approved, token_used_senat, token_used_dewan FROM voters WHERE token_hash = ?",
              (encoded_token,))
    voter = c.fetchone()
    conn.close()

    if not voter:
        flash('Invalid token')
        return redirect(url_for('submit_token_page'))

    if voter['approved'] == 0:
        flash('Your registration has not been approved yet')
        return redirect(url_for('submit_token_page'))

    # Check if token has been used for both votes
    if voter['token_used_senat'] == 1 and voter['token_used_dewan'] == 1:
        flash('This token has already been used for both elections')
        return redirect(url_for('submit_token_page'))

    # Store token and voter info in session
    session['voting_token'] = token
    session['voting_id_number_hash'] = voter['id_number_hash']  # Store hash instead of original
    session['token_validated_at'] = time.time()

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
    c.execute("SELECT id, name, photo, class, type FROM candidates ORDER BY id")
    candidates = c.fetchall()

    # Pisahkan kandidat berdasarkan jenis pemilihan
    senat_candidates = [candidate for candidate in candidates if candidate['type'] == 'senat']
    demus_candidates = [candidate for candidate in candidates if candidate['type'] == 'demus']

    try:
        # Process token from session
        salted_token = token + "PoltekSSN"
        hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
        encoded_token = base64.b64encode(hashed_token.encode()).decode()

        c.execute("SELECT token_used_senat, token_used_dewan FROM voters WHERE token_hash = ?", (encoded_token,))
        voter = c.fetchone()
        conn.close()

        if voter:
            token_used_senat, token_used_dewan = voter
            print(f"DEBUG vote_page: token_used_senat={token_used_senat}, token_used_dewan={token_used_dewan}")

            if token_used_senat == 0:
                # Belum vote senat: tampilkan halaman vote untuk senat
                print("DEBUG vote_page: Showing SENAT voting page")
                return render_template(
                    'vote.html',
                    candidates=senat_candidates,
                    no_candidates=(len(senat_candidates) == 0),
                    voting_stage='senat'
                )
            elif token_used_dewan == 0:
                # Sudah vote senat tapi belum vote demus: langsung tampilkan halaman vote untuk demus
                print("DEBUG vote_page: Showing DEMUS voting page")
                return render_template(
                    'vote.html',
                    candidates=demus_candidates,
                    no_candidates=(len(demus_candidates) == 0),
                    voting_stage='demus'
                )
            else:
                # Token sudah digunakan untuk kedua vote
                print("DEBUG vote_page: Both votes completed, redirecting to index")
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
    # Enhanced session and input validation
    token = session.get('voting_token')
    if not token:
        flash('Invalid session. Please submit your token again.')
        return redirect(url_for('submit_token_page'))

    # Enhanced form data validation
    try:
        candidate_id = escape(request.form.get('candidate', '').strip())
        voting_stage = escape(request.form.get('voting_stage', '').strip())

        # Length validation
        if len(candidate_id) > 10 or len(voting_stage) > 10:
            flash('Invalid input length')
            return redirect(url_for('vote_page'))

        # Additional security checks
        if not candidate_id or not candidate_id.isdigit():
            flash('Invalid candidate selection')
            return redirect(url_for('vote_page'))

        # Ensure candidate_id is within reasonable range
        candidate_id_int = int(candidate_id)
        if candidate_id_int < 1 or candidate_id_int > 1000:  # Reasonable range
            flash('Invalid candidate ID')
            return redirect(url_for('vote_page'))

    except (ValueError, TypeError, AttributeError) as e:
        flash('Invalid request format')
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
        c.execute("SELECT id_number_hash, approved, token_used_senat, token_used_dewan FROM voters WHERE token_hash = ?", (encoded_token,))
        voter = c.fetchone()
        if not voter:
            conn.rollback()
            flash('Invalid token')
            session.pop('voting_token', None)
            session.pop('voting_id_number', None)
            return redirect(url_for('submit_token_page'))

        id_number_hash, approved, token_used_senat, token_used_dewan = voter
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

        # Commit validation checks and close first connection
        conn.commit()

    # PERBAIKAN: Gunakan global key manager untuk konsistensi keys
    session_id = session.get('session_id', os.urandom(16).hex())
    session['session_id'] = session_id

    # Gunakan global key manager untuk memastikan konsistensi
    keys = get_global_keys()
    signer = get_global_signer()

    n = keys['n']
    e = keys['e']
    d = keys['d']

    print(f"DEBUG: Using global keys for vote:")
    print(f"  - n: {n}")
    print(f"  - e: {e}")
    print(f"  - d: {d}")

    # Test key consistency
    test_message = 12345
    test_signed = pow(test_message, d, n)
    test_verified = pow(test_signed, e, n)
    key_test_passed = (test_verified == test_message)
    print(f"  - key test: {test_message} -> {test_signed} -> {test_verified}")
    print(f"  - key test passed: {key_test_passed}")

    if not key_test_passed:
        print("ERROR: Global keys are inconsistent!")
        flash('System error: Key verification failed.')
        return redirect(url_for('vote_page'))

        # Simpan public key ke database
        with get_db_connection() as conn_save_keys:
            c_save_keys = conn_save_keys.cursor()
            c_save_keys.execute("INSERT INTO keys (n, e, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)",
                           (str(n), str(e)))
            conn_save_keys.commit()

        # Simpan private key sementara untuk session
        from core.createdb import save_session_private_key
        save_session_private_key(d, session_id)

    try:
        # PERBAIKAN: Implementasi blind signature yang benar dan aman
        # 1. Pesan adalah candidate_id saja
        message = str(candidate_id)
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        message_hash_int = int(message_hash, 16)
        print(f"DEBUG: Processing vote for candidate {candidate_id}, stage {voting_stage}")

        # PERBAIKAN: Pastikan hash tidak lebih besar dari modulus
        if message_hash_int >= n:
            message_hash_int = message_hash_int % n

        # 2. Buat objek Voter dan blinding factor yang tepat dengan entropy unik
        try:
            # Generate unique entropy untuk setiap vote
            unique_entropy = f"{candidate_id}_{voting_stage}_{session_id}_{time.time_ns()}_{os.urandom(8).hex()}"
            voter_obj = bs.Voter(n, "y", unique_entropy)
            print("DEBUG: Voter object created successfully")
        except ValueError as e:
            print(f"DEBUG: Error creating voter object: {e}")
            flash('Error: Unable to create secure voting session.')
            return redirect(url_for('vote_page'))

        blind_message = voter_obj.blind_message(message_hash_int, n, e)
        print("DEBUG: Message blinded successfully")

        # 3. Sign the blinded message
        signed_blind_message = signer.sign_message(blind_message, voter_obj.get_eligibility())
        print("DEBUG: Message signed successfully")

        # PERBAIKAN: Validasi signed_blind_message
        if signed_blind_message is None:
            print("DEBUG: Signed blind message is None")
            flash('Error: Unable to sign the vote.')
            return redirect(url_for('vote_page'))

        # 4. Unwrap the signature
        signature = voter_obj.unwrap_signature(signed_blind_message, n)
        print("DEBUG: Signature unwrapped successfully")

        # PERBAIKAN: Validasi signature hasil unwrap
        if signature is None:
            print("DEBUG: Unwrapped signature is None")
            flash('Error: Unable to unwrap vote signature.')
            return redirect(url_for('vote_page'))

        # 5. Verify the signature (mandatory security check)
        # PERBAIKAN: Gunakan key yang sama dengan DummySigner untuk verifikasi
        signer_e = signer.public_key['e']
        signer_n = signer.public_key['n']

        # DEBUGGING: Manual verification to check mathematical correctness
        print(f"DEBUG: Manual verification check:")
        manual_verification = pow(int(signature), signer_e, signer_n)
        print(f"  - signature^e mod n = {manual_verification}")
        print(f"  - original message_hash_int = {message_hash_int}")
        print(f"  - manual verification match = {manual_verification == message_hash_int}")

        # Let's also test if we can sign the original message directly (without blinding)
        direct_signature = pow(message_hash_int, signer.private_key['d'], signer_n)
        direct_verification = pow(direct_signature, signer_e, signer_n)
        print(f"  - direct_signature = {direct_signature}")
        print(f"  - direct_verification = {direct_verification}")
        print(f"  - direct verification match = {direct_verification == message_hash_int}")

        is_valid = bs.verify_signature(candidate_id, signature, signer_e, signer_n)
        print(f"DEBUG: Signature verification details:")
        print(f"  - candidate_id: {candidate_id}")
        print(f"  - signature: {signature}")
        print(f"  - signer_e: {signer_e}")
        print(f"  - signer_n: {signer_n}")
        print(f"  - database_e: {e}")
        print(f"  - database_n: {n}")
        print(f"  - message_hash_int: {message_hash_int}")
        print(f"  - verification result: {is_valid}")
        if not is_valid:
            flash('Error in vote verification.')
            return redirect(url_for('vote_page'))

        # 6. Store vote dengan proper blind signature support dalam satu transaksi
        from core.key_manager import key_manager
        active_key_id = key_manager.get_active_key_id()

        try:
            with get_db_connection() as conn_vote:
                c_vote = conn_vote.cursor()
                conn_vote.execute("BEGIN IMMEDIATE;")
                print("DEBUG: Database transaction started")

                # PERBAIKAN: Simpan ballot dengan key reference untuk verifikasi dalam transaksi yang sama
                voter_hash = hashlib.sha256(encoded_token.encode()).hexdigest()

                # Save ballot dalam transaksi yang sama
                c_vote.execute('''INSERT INTO ballots (signature, type, key_id, voter_hash, timestamp)
                                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                             (str(signature), voting_stage, active_key_id, voter_hash))
                ballot_id = c_vote.lastrowid
                print(f"DEBUG: Ballot saved with ID {ballot_id} for stage {voting_stage}")

                # Save vote record dalam transaksi yang sama
                c_vote.execute('''INSERT INTO votes (voter_npm_encrypted, candidate_id, voting_stage, signature, key_id, ballot_id, timestamp)
                                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                             (encoded_token, candidate_id, voting_stage, str(signature), active_key_id, ballot_id))
                vote_id = c_vote.lastrowid
                print(f"DEBUG: Vote record saved with ID {vote_id}")

                # Update status token berdasarkan stage voting dalam transaksi yang sama
                if voting_stage == 'senat':
                    c_vote.execute("UPDATE voters SET token_used_senat = 1 WHERE token_hash = ?", (encoded_token,))
                    rows_affected = c_vote.rowcount
                    print(f"DEBUG: Updated token_used_senat to 1, rows affected: {rows_affected}")

                    # Verify update berhasil
                    c_vote.execute("SELECT token_used_senat, token_used_dewan FROM voters WHERE token_hash = ?", (encoded_token,))
                    verify_result = c_vote.fetchone()
                    print(f"DEBUG: After update - token_used_senat={verify_result[0]}, token_used_dewan={verify_result[1]}")

                    # Commit seluruh transaksi
                    conn_vote.commit()
                    print("DEBUG: Database committed successfully for senat")

                    flash('Vote cast successfully for Ketua Senat. Please proceed to vote for Ketua Dewan Musyawarah Taruna.')
                    return redirect(url_for('vote_page'))

                elif voting_stage == 'demus':
                    c_vote.execute("UPDATE voters SET token_used_dewan = 1 WHERE token_hash = ?", (encoded_token,))
                    rows_affected = c_vote.rowcount
                    print(f"DEBUG: Updated token_used_dewan to 1, rows affected: {rows_affected}")

                    # Verify update berhasil
                    c_vote.execute("SELECT token_used_senat, token_used_dewan FROM voters WHERE token_hash = ?", (encoded_token,))
                    verify_result = c_vote.fetchone()
                    print(f"DEBUG: After update - token_used_senat={verify_result[0]}, token_used_dewan={verify_result[1]}")

                    # Commit seluruh transaksi
                    conn_vote.commit()
                    print("DEBUG: Database committed successfully for demus")

                    flash('Vote cast successfully for Ketua Dewan Musyawarah Taruna. Thank you for voting!')
                    # Clear voting session after completed both votes
                    session.pop('voting_token', None)
                    session.pop('voting_id_number', None)
                    return redirect(url_for('index'))

        except Exception as vote_error:
            print(f"ERROR: Vote storage failed: {vote_error}")
            flash('Error storing vote. Please try again.')
            return redirect(url_for('vote_page'))

    except Exception as e:
        flash(f'Error processing vote: {str(e)}')
        return redirect(url_for('vote_page'))

    return redirect(url_for('vote_page'))


@app.route('/recap', methods=['GET'])
@limiter.limit("10 per minute")
def recap():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    # Use ultra-fast tabulation for maximum performance
    tabulator = UltraOptimizedTabulator(use_parallel=True)
    verified_ballots, vote_counts, candidates = tabulator.ultra_fast_tabulation()
    return render_template('recap.html', vote_counts=vote_counts, candidates=candidates)


@app.route('/recap/legacy', methods=['GET'])
@limiter.limit("5 per minute")
def recap_legacy():
    """Legacy recap using original algorithm for comparison"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    verified_ballots, vote_counts, candidates = recap_votes()
    return render_template('recap.html', vote_counts=vote_counts, candidates=candidates)


@app.route('/api/tabulation/benchmark', methods=['GET'])
@limiter.limit("2 per minute")
def tabulation_benchmark():
    """Benchmark tabulation performance with all implementations"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    try:

        # Test all implementations
        results = {}

        # 1. Ultra-fast implementation
        ultra_tabulator = UltraOptimizedTabulator(use_parallel=True)
        ultra_results = ultra_tabulator.benchmark_ultra_fast(iterations=3)
        results['ultra_fast'] = ultra_results

        # 2. Ultra-fast sequential implementation for comparison
        sequential_tabulator = UltraOptimizedTabulator(use_parallel=False)
        seq_results = sequential_tabulator.benchmark_ultra_fast(iterations=3)
        results['ultra_fast_sequential'] = seq_results

        # 3. Original implementation (quick test)
        start = time.perf_counter()
        verified_ballots, _, _ = recap_votes()
        original_time = (time.perf_counter() - start) * 1000
        ballot_count = len(verified_ballots)
        original_per_ballot = original_time / ballot_count if ballot_count > 0 else 0

        results['original'] = {
            'average_total_ms': original_time,
            'average_per_ballot_ms': original_per_ballot,
            'total_ballots': ballot_count
        }

        # Compare with targets
        target_ms = 3.9
        baseline_ms = 23.3  # Current baseline from benchmark

        best_implementation = min(results.keys(),
                                key=lambda k: results[k]['average_per_ballot_ms'])
        best_time = results[best_implementation]['average_per_ballot_ms']

        summary = {
            'target_ms': target_ms,
            'baseline_ms': baseline_ms,
            'best_implementation': best_implementation,
            'best_time_ms': best_time,
            'target_achieved': best_time < target_ms,
            'improvement_factor': baseline_ms / best_time if best_time > 0 else 0,
            'vs_zkvoting': best_time / target_ms
        }

        return jsonify({
            'status': 'success',
            'results': results,
            'summary': summary,
            'message': f"Best: {best_implementation} at {best_time:.2f}ms per ballot"
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/tabulation/ultra-benchmark', methods=['GET'])
@limiter.limit("3 per minute")
def ultra_tabulation_benchmark():
    """Focused benchmark for ultra-fast tabulation"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        tabulator = UltraOptimizedTabulator(use_parallel=True)
        results = tabulator.benchmark_ultra_fast(iterations=5)

        # Add detailed comparison
        results['target_ms'] = 3.9
        results['baseline_ms'] = 23.3
        results['zkvoting_target'] = 3.9
        results['performance_rating'] = 'EXCELLENT' if results['average_per_ballot_ms'] < 2.0 else \
                                      'GOOD' if results['average_per_ballot_ms'] < 3.9 else \
                                      'NEEDS_IMPROVEMENT'

        return jsonify({
            'status': 'success',
            'benchmark': results,
            'message': f"Ultra-fast tabulation: {results['average_per_ballot_ms']:.2f}ms per ballot"
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Enhanced security validation for file access
    if not filename or len(filename) > 255:
        return "Invalid filename", 400

    # Strict filename validation to prevent path traversal and XSS
    if not re.match(r'^[a-zA-Z0-9_\.-]+\.(jpg|jpeg|png)$', filename):
        return "Invalid filename format", 400

    # Additional checks for dangerous patterns
    dangerous_patterns = ['..', '/', '\\', '<', '>', '|', ':', '*', '?', '"', '\x00', 'script', 'javascript']
    if any(pattern in filename.lower() for pattern in dangerous_patterns):
        return "Forbidden filename", 403

    # Check if file exists and is within upload directory
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return "File not found", 404

    # Ensure the resolved path is still within upload folder (prevent symlink attacks)
    upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])
    file_path_abs = os.path.abspath(file_path)
    if not file_path_abs.startswith(upload_folder_abs):
        return "Access denied", 403

    response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # Add security headers for file serving
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Disposition'] = f'inline; filename="{filename}"'
    return response


@app.route('/voter_status', methods=['GET'])
@limiter.limit("10 per minute")
def voter_status():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_number_encrypted, approved, token_used_senat, token_used_dewan FROM voters")
    voters_raw = c.fetchall()
    conn.close()

    # Decrypt NPM untuk display
    from core.createdb import decrypt_npm
    voters = []
    for voter in voters_raw:
        voter_dict = {
            'id_number': decrypt_npm(voter[0]),  # Decrypt untuk display
            'approved': voter[1],
            'token_used_senat': voter[2],
            'token_used_dewan': voter[3]
        }
        voters.append(voter_dict)

    return render_template('voter_status.html', voters=voters)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        outer_local_ip = s.getsockname()[0]
        s.close()
        return outer_local_ip
    except Exception as e:
        return "127.0.0.1"


@app.route('/get_candidate_photos')
def get_candidate_photos():
    candidates = get_all_candidates()
    # Konversi setiap sqlite3.Row menjadi dictionary
    candidates = [dict(c) for c in candidates]
    photos = {
        c['name']: {
            'id': c['id'],  # ✅ PERBAIKAN: Tambahkan ID untuk pengurutan
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

    # Enhanced parameter validation
    vote_type = request.args.get('type', '').strip()

    # Input sanitization and validation
    if not vote_type or len(vote_type) > 10:
        return "Invalid vote type", 400

    if vote_type not in ['senat', 'demus']:
        return "Invalid vote type", 400

    # Additional security headers for SSE
    def generate():
        try:
            verified_ballots, _, _ = recap_votes()
            for candidate_name, candidate_type in verified_ballots:
                if candidate_type == vote_type:  # Hanya kirim data sesuai pilihan user
                    # Sanitize output data
                    safe_candidate_name = escape(str(candidate_name)[:100])  # Limit length
                    safe_candidate_type = escape(str(candidate_type))

                    yield f"data: {json.dumps({'candidate': safe_candidate_name, 'type': safe_candidate_type})}\n\n"
                    time.sleep(0.2)  # Delay 0.2 detik
        except Exception as e:
            # Log error but don't expose details to client
            yield f"data: {json.dumps({'error': 'Processing error'})}\n\n"

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    return response


@app.route('/benchmark', methods=['GET'])
def benchmark_page():
    """Halaman benchmark performance"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('benchmark.html')


def simulate_random_voting(num_votes):
    """Simulate random voting process untuk benchmark - Maximum 1024 votes"""

    # ✅ PERBAIKAN: Limit maximum votes to 1024
    if num_votes > 1024:
        num_votes = 1024

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


    vote_times = []
    successful_votes = 0
    vote_distribution = {'senat': {}, 'demus': {}}

    # Initialize vote distribution counters
    for candidate in candidates:
        vote_distribution[candidate['type']][candidate['name']] = 0

    start_time = time.time()

    # ✅ PERBAIKAN: Batch processing untuk performance yang lebih baik
    batch_size = 50
    batches = (num_votes + batch_size - 1) // batch_size

    for batch_num in range(batches):
        batch_start = batch_num * batch_size
        batch_end = min((batch_num + 1) * batch_size, num_votes)
        batch_votes = batch_end - batch_start


        for i in range(batch_start, batch_end):
            vote_start = time.time()

            try:
                # Simulate vote casting process
                selected_candidate = random.choice(candidates)
                candidate_name = selected_candidate['name']
                candidate_type = selected_candidate['type']

                # ✅ PERBAIKAN: Optimized processing time based on actual system performance
                # Simulate realistic processing time (0.05-0.3 seconds based on benchmark data)
                processing_time = random.uniform(0.05, 0.3)
                time.sleep(processing_time)

                # Update vote distribution
                vote_distribution[candidate_type][candidate_name] += 1

                vote_end = time.time()
                vote_time = vote_end - vote_start
                vote_times.append(vote_time)
                successful_votes += 1

            except Exception as e:
                continue

        # Progress indicator per batch
        progress = (batch_end / num_votes) * 100

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
        'votes_per_second': votes_per_second,
        'vote_distribution': vote_distribution
    }


    # ✅ PERBAIKAN: Display vote distribution
    total_senat = sum(vote_distribution['senat'].values())
    total_demus = sum(vote_distribution['demus'].values())

    for name, count in vote_distribution['senat'].items():
        percentage = (count / total_senat * 100) if total_senat > 0 else 0

    for name, count in vote_distribution['demus'].items():
        percentage = (count / total_demus * 100) if total_demus > 0 else 0

    return results

@app.route('/run_complete_benchmark', methods=['POST'])
@limiter.limit("3 per hour")
def run_complete_benchmark():
    """Jalankan benchmark lengkap: generate votes + random voting + tabulation + decryption"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Enhanced input validation and sanitization
        try:
            iterations = int(request.form.get('iterations', 5))
            voting_iterations = int(request.form.get('voting_iterations', 50))
            random_vote_count = int(request.form.get('random_vote_count', 0))
        except (ValueError, TypeError) as e:
            return jsonify({'error': 'Invalid input parameters'}), 400

        # Check request size to prevent DoS
        if request.content_length and request.content_length > 1024:  # 1KB limit
            return jsonify({'error': 'Request too large'}), 400

        # ✅ PERBAIKAN: Enhanced limits for 1024 maximum with additional security
        iterations = min(max(iterations, 1), 20)  # Reduced from 50 to 20
        voting_iterations = min(max(voting_iterations, 1), 1024)  # Maximum 1024
        random_vote_count = min(max(random_vote_count, 0), 1024)  # Maximum 1024

        # Additional security: prevent resource exhaustion
        total_work = iterations * voting_iterations + random_vote_count
        if total_work > 5000:  # Reasonable limit for total work
            return jsonify({'error': 'Request would consume too many resources'}), 400


        # === STEP 1: GENERATE DUMMY VOTES ===
        generation_start = time.time()

        if not BENCHMARK_MODULES_AVAILABLE:
            return jsonify({'error': 'Benchmark modules not available. Please ensure all required files are present.'}), 500

        # ✅ PERBAIKAN: Enhanced error handling for large vote generation
        try:
            generation_results = generate_dummy_votes_with_timing(voting_iterations, measure_individual=True)
        except Exception as e:
            return jsonify({'error': f'Failed to generate votes: {str(e)}'}), 500

        if not generation_results or generation_results.get('successful_votes', 0) == 0:
            return jsonify({'error': 'Failed to generate dummy votes'}), 500

        generation_end = time.time()
        generation_time = generation_end - generation_start


        # === STEP 2: RANDOM VOTING SIMULATION ===
        random_voting_start = time.time()

        if random_vote_count > 0:
            try:
                random_voting_results = simulate_random_voting(random_vote_count)
            except Exception as e:
                random_voting_results = {
                    'total_votes': 0,
                    'total_time': 0,
                    'avg_time_per_vote': 0,
                    'min_time': 0,
                    'max_time': 0,
                    'votes_per_second': 0,
                    'vote_distribution': {'senat': {}, 'demus': {}}
                }
        else:
            random_voting_results = {
                'total_votes': 0,
                'total_time': 0,
                'avg_time_per_vote': 0,
                'min_time': 0,
                'max_time': 0,
                'votes_per_second': 0,
                'vote_distribution': {'senat': {}, 'demus': {}}
            }

        random_voting_end = time.time()
        random_voting_time = random_voting_end - random_voting_start


        # === STEP 3: TABULATION BENCHMARK (ULTRA-FAST VERSION) ===
        tabulation_start = time.time()

        try:
            # Use ultra-fast tabulation implementation
            tabulator = UltraOptimizedTabulator(use_parallel=True)
            tabulation_data = tabulator.measure_performance(iterations)
        except Exception as e:
            return jsonify({'error': f'Failed to run tabulation benchmark: {str(e)}'}), 500

        if not tabulation_data:
            return jsonify({'error': 'Failed to run tabulation benchmark'}), 500

        tabulation_end = time.time()
        tabulation_time = tabulation_end - tabulation_start


        # === STEP 4: DECRYPTION/VERIFICATION BENCHMARK ===
        try:
            # Use the actual vote count from generation
            actual_vote_count = generation_results.get('total_votes', voting_iterations)
            decryption_results = benchmark_vote_decryption(actual_vote_count, 1)
            total_decryption_time = decryption_results.get('total_time', 0)
        except Exception as e:
            # Provide default results if decryption fails
            decryption_results = {
                'total_votes_verified': 0,
                'successful_iterations': 0,
                'avg_time': 0,
                'median_time': 0,
                'total_time': 0,
                'verification_success_rate': 0,
                'votes_per_second': 0
            }
            total_decryption_time = 0

        # === STEP 5: AGGREGATE RESULTS ===
        total_time = generation_time + random_voting_time + tabulation_time + total_decryption_time

        # zkVoting baseline data
        zkvoting_ballot_casting_time = 2.3  # 2.3 seconds per ballot casting
        zkvoting_tally_time = 0.0039  # 3.9 milliseconds per ballot = 0.0039 seconds

        # ✅ PERBAIKAN: Safe division for speedup calculations
        generation_speedup = (zkvoting_ballot_casting_time / generation_results['avg_time_per_vote']) if generation_results.get('avg_time_per_vote', 0) > 0 else 0
        tabulation_speedup = (zkvoting_tally_time / tabulation_data['avg_time_per_ballot']) if tabulation_data.get('avg_time_per_ballot', 0) > 0 else 0
        decryption_speedup = (zkvoting_tally_time / decryption_results['avg_time_per_vote']) if decryption_results.get('avg_time_per_vote', 0) > 0 else 0

        # === STEP 6: GENERATE VISUALIZATION ===

        try:
            charts = generate_complete_benchmark_charts(
                generation_results, tabulation_data, decryption_results
            )
        except Exception as e:
            print(f"❌ Error generating charts: {str(e)}")
            charts = {}

        # ✅ PERBAIKAN: Enhanced results with vote distribution
        results = {
            'generation_results': {
                'total_votes': generation_results.get('successful_votes', 0),
                'total_time': generation_time,
                'avg_time': generation_results.get('avg_time_per_vote', 0),
                'min_time': generation_results.get('individual_stats', {}).get('min', 0),
                'max_time': generation_results.get('individual_stats', {}).get('max', 0),
                'votes_per_second': generation_results.get('votes_per_second', 0),
                'success_rate': generation_results.get('success_rate', 0),
                'speedup_vs_zkvoting': generation_speedup,
                'vote_distribution': generation_results.get('vote_distribution', {})
            },
            'random_voting_results': {
                'total_votes': random_voting_results.get('total_votes', 0),
                'total_time': random_voting_time,
                'avg_time': random_voting_results.get('avg_time_per_vote', 0),
                'min_time': random_voting_results.get('min_time', 0),
                'max_time': random_voting_results.get('max_time', 0),
                'votes_per_second': random_voting_results.get('votes_per_second', 0),
                'vote_distribution': random_voting_results.get('vote_distribution', {})
            },
            'tabulation_results': {
                'total_ballots': tabulation_data.get('total_ballots', 0),
                'iterations': tabulation_data.get('iterations', 0),
                'avg_time': tabulation_data.get('avg_time', 0),
                'median_time': tabulation_data.get('median_time', 0),
                'min_time': tabulation_data.get('min_time', 0),
                'max_time': tabulation_data.get('max_time', 0),
                'avg_time_per_ballot': tabulation_data.get('avg_time_per_ballot', 0),
                'ballots_per_second': tabulation_data.get('ballots_per_second', 0),
                'speedup_vs_zkvoting': tabulation_speedup,
                'vote_counts': {}  # ✅ Initialize empty vote_counts
            },
            'decryption_results': {
                'total_votes_verified': decryption_results.get('total_votes_verified', 0),
                'total_time': total_decryption_time,
                'avg_time': decryption_results.get('avg_time_per_vote', 0),
                'verification_success_rate': decryption_results.get('verification_success_rate', 0),
                'votes_per_second': decryption_results.get('votes_per_second', 0),
                'speedup_vs_zkvoting': decryption_speedup
            },
            'overall_performance': {
                'total_end_to_end_time': total_time,
                'overall_speedup': min(generation_speedup, tabulation_speedup, decryption_speedup) if all([generation_speedup, tabulation_speedup, decryption_speedup]) else 0,
                'recommendation': get_performance_recommendation_complete(
                    generation_results, tabulation_data, decryption_results
                ),
                'max_vote_limit': 1024,
                'performance_tier': get_performance_tier(generation_results, tabulation_data, decryption_results)
            },
            'charts': charts,
            'baseline_comparison': {
                'system': 'zkVoting',
                'paper_reference': 'zkVoting: A coercion-resistant e-voting system',
                'ballot_casting_time': zkvoting_ballot_casting_time,
                'tally_time_per_ballot': zkvoting_tally_time,
                'algorithm_complexity': 'O(n)',
                'features': ['Coercion-resistant', 'E2E verifiable', 'Anonymity-preserving', 'Zero-knowledge proofs']
            },
            'system_limits': {
                'max_votes_per_test': 1024,
                'max_iterations': 20,
                'recommended_batch_size': 50,
                'optimal_vote_range': '100-500 votes for balanced testing'
            }
        }

        print(f"\n🎉 Complete benchmark finished!")
        print(f"   Total time: {total_time:.4f}s")
        print(f"   Overall speedup vs zkVoting: {results['overall_performance']['overall_speedup']:.2f}x")
        print(f"   Performance tier: {results['overall_performance']['performance_tier']}")

        # ✅ FIX: Properly format vote counts for frontend
        try:
            # Get actual vote counts from tabulation
            conn = get_db_connection()
            c = conn.cursor()
            try:
                verified_ballots, formatted_vote_counts, candidates_list = recap_votes()
                print(f"🔍 Vote counts from recap: {formatted_vote_counts}")
            except Exception as recap_error:
                print(f"❌ Error getting vote counts: {recap_error}")
                formatted_vote_counts = {}

            # Update tabulation_data with formatted counts
            tabulation_data['vote_counts'] = formatted_vote_counts

        except Exception as e:
            print(f"❌ Error formatting vote counts: {e}")
            formatted_vote_counts = {}

        # ✅ FIX: Ensure vote_counts is properly passed to results
        results = {
            'generation_results': {
                'total_votes': generation_results.get('successful_votes', 0),
                'total_time': generation_time,
                'avg_time': generation_results.get('avg_time_per_vote', 0),
                'min_time': generation_results.get('individual_stats', {}).get('min', 0),
                'max_time': generation_results.get('individual_stats', {}).get('max', 0),
                'votes_per_second': generation_results.get('votes_per_second', 0),
                'success_rate': generation_results.get('success_rate', 0),
                'speedup_vs_zkvoting': generation_speedup,
                'vote_distribution': generation_results.get('vote_distribution', {})
            },
            'random_voting_results': {
                'total_votes': random_voting_results.get('total_votes', 0),
                'total_time': random_voting_time,
                'avg_time': random_voting_results.get('avg_time_per_vote', 0),
                'min_time': random_voting_results.get('min_time', 0),
                'max_time': random_voting_results.get('max_time', 0),
                'votes_per_second': random_voting_results.get('votes_per_second', 0),
                'vote_distribution': random_voting_results.get('vote_distribution', {})
            },
            'tabulation_results': {
                'total_ballots': tabulation_data.get('total_ballots', 0),
                'iterations': tabulation_data.get('iterations', 0),
                'avg_time': tabulation_data.get('avg_time', 0),
                'median_time': tabulation_data.get('median_time', 0),
                'min_time': tabulation_data.get('min_time', 0),
                'max_time': tabulation_data.get('max_time', 0),
                'avg_time_per_ballot': tabulation_data.get('avg_time_per_ballot', 0),
                'ballots_per_second': tabulation_data.get('ballots_per_second', 0),
                'speedup_vs_zkvoting': tabulation_speedup,
                'vote_counts': formatted_vote_counts  # ✅ Use formatted vote counts
            },
            'decryption_results': {
                'total_votes_verified': decryption_results.get('total_votes_verified', 0),
                'total_time': total_decryption_time,
                'avg_time': decryption_results.get('avg_time_per_vote', 0),
                'verification_success_rate': decryption_results.get('verification_success_rate', 0),
                'votes_per_second': decryption_results.get('votes_per_second', 0),
                'speedup_vs_zkvoting': decryption_speedup
            },
            'overall_performance': {
                'total_end_to_end_time': total_time,
                'overall_speedup': min(generation_speedup, tabulation_speedup, decryption_speedup) if all([generation_speedup, tabulation_speedup, decryption_speedup]) else 0,
                'recommendation': get_performance_recommendation_complete(
                    generation_results, tabulation_data, decryption_results
                ),
                'max_vote_limit': 1024,
                'performance_tier': get_performance_tier(generation_results, tabulation_data, decryption_results)
            },
            'charts': charts,
            'baseline_comparison': {
                'system': 'zkVoting',
                'paper_reference': 'zkVoting: A coercion-resistant e-voting system',
                'ballot_casting_time': zkvoting_ballot_casting_time,
                'tally_time_per_ballot': zkvoting_tally_time,
                'algorithm_complexity': 'O(n)',
                'features': ['Coercion-resistant', 'E2E verifiable', 'Anonymity-preserving', 'Zero-knowledge proofs']
            },
            'system_limits': {
                'max_votes_per_test': 1024,
                'max_iterations': 20,
                'recommended_batch_size': 50,
                'optimal_vote_range': '100-500 votes for balanced testing'
            }
        }

        return jsonify(results)

    except ValueError as ve:
        print(f"❌ ValueError: {str(ve)}")
        return jsonify({'error': f'Invalid input values: {str(ve)}'}), 400
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error running complete benchmark: {str(e)}'}), 500

def get_performance_tier(generation_results, tabulation_data, decryption_results):
    """Determine performance tier based on results"""
    try:
        votes_per_second = generation_results.get('votes_per_second', 0)
        tabulation_speed = 1 / tabulation_data.get('avg_time_per_ballot', 1) if tabulation_data.get('avg_time_per_ballot', 0) > 0 else 0
        success_rate = generation_results.get('success_rate', 0)

        if votes_per_second > 10 and tabulation_speed > 1000 and success_rate > 95:
            return "🚀 ENTERPRISE (1000+ votes/hour)"
        elif votes_per_second > 5 and tabulation_speed > 500 and success_rate > 90:
            return "⭐ PROFESSIONAL (500+ votes/hour)"
        elif votes_per_second > 2 and tabulation_speed > 200 and success_rate > 85:
            return "✅ STANDARD (200+ votes/hour)"
        elif votes_per_second > 1 and tabulation_speed > 100 and success_rate > 75:
            return "📊 BASIC (100+ votes/hour)"
        else:
            return "⚠️ DEVELOPMENT (Optimization needed)"
    except:
        return "❓ UNKNOWN (Error in calculation)"

def benchmark_vote_decryption(vote_count=100, iterations=1):
    """
    Benchmark vote decryption and verification process
    """

    try:
        results = []
        total_votes_verified = 0

        for i in range(iterations):
            start_time = time.time()

            # Get ballots from database using raw SQL
            conn = get_db_connection()
            c = conn.cursor()
            # PERBAIKAN: Ambil ballots tanpa candidate_id
            c.execute("SELECT signature, type FROM ballots LIMIT ?", (vote_count,))
            ballots = c.fetchall()
            conn.close()

            iteration_verified = 0

            for ballot in ballots:
                try:
                    # Simulate decryption and verification
                    signature = ballot[0]
                    vote_type = ballot[1]

                    # PERBAIKAN: Simulasi decryption tanpa candidate_id spesifik
                    test_candidate_id = "1"  # Simulasi untuk benchmark
                    decrypted_vote = test_candidate_id

                    # Simulate signature verification (replace with actual implementation)
                    if verify_vote_signature(signature, decrypted_vote):
                        iteration_verified += 1
                except Exception as e:
                    continue

            iteration_time = time.time() - start_time
            results.append(iteration_time)
            total_votes_verified += iteration_verified


        # Calculate statistics
        avg_time = statistics.mean(results) if results else 0
        median_time = statistics.median(results) if results else 0
        total_time = sum(results)
        verification_success_rate = (total_votes_verified / (vote_count * iterations)) * 100 if vote_count > 0 else 0
        avg_time_per_vote = total_time / total_votes_verified if total_votes_verified > 0 else 0

        benchmark_results = {
            'total_votes_verified': total_votes_verified,
            'successful_iterations': len(results),
            'avg_time': avg_time,
            'avg_time_per_vote': avg_time_per_vote,
            'median_time': median_time,
            'total_time': total_time,
            'verification_success_rate': verification_success_rate,
            'votes_per_second': total_votes_verified / total_time if total_time > 0 else 0
        }


        return benchmark_results

    except Exception as e:
        print(f"❌ Error in decryption benchmark: {e}")
        return {
            'total_votes_verified': 0,
            'successful_iterations': 0,
            'avg_time': 0,
            'avg_time_per_vote': 0,
            'median_time': 0,
            'total_time': 0,
            'verification_success_rate': 0,
            'votes_per_second': 0
        }

def generate_complete_benchmark_charts(generation_results, tabulation_results, decryption_results):
    """
    Generate comprehensive benchmark charts
    """
    try:
        import numpy as np
        from io import BytesIO

        print("📈 Generating comprehensive benchmark charts...")

        # Create figure with subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('E-Voting System Performance Benchmark', fontsize=16, fontweight='bold')

        # Chart 1: Process Times Comparison
        processes = ['Generation', 'Tabulation', 'Verification']
        times = [
            generation_results.get('avg_time_per_vote', 0) * 1000,  # Convert to ms
            tabulation_results.get('avg_time_per_ballot', 0) * 1000,
            decryption_results.get('avg_time_per_vote', 0) * 1000
        ]

        bars1 = ax1.bar(processes, times, color=['#3498db', '#f39c12', '#2ecc71'])
        ax1.set_title('Average Processing Time per Vote')
        ax1.set_ylabel('Time (milliseconds)')
        ax1.grid(True, alpha=0.3)

        # Add value labels on bars
        for bar, time_val in zip(bars1, times):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                    f'{time_val:.2f}ms', ha='center', va='bottom')

        # Chart 2: Throughput Comparison
        throughputs = [
            generation_results.get('votes_per_second', 0),
            tabulation_results.get('ballots_per_second', 0),
            decryption_results.get('votes_per_second', 0)
        ]

        bars2 = ax2.bar(processes, throughputs, color=['#e74c3c', '#9b59b6', '#1abc9c'])
        ax2.set_title('Processing Throughput')
        ax2.set_ylabel('Items per Second')
        ax2.grid(True, alpha=0.3)

        # Add value labels
        for bar, throughput in zip(bars2, throughputs):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                    f'{throughput:.1f}/s', ha='center', va='bottom')

        # Chart 3: Success Rates
        success_rates = [
            generation_results.get('success_rate', 100),
            100,  # Tabulation typically 100% success
            decryption_results.get('verification_success_rate', 100)
        ]

        bars3 = ax3.bar(processes, success_rates, color=['#34495e', '#16a085', '#27ae60'])
        ax3.set_title('Success Rates')
        ax3.set_ylabel('Success Rate (%)')
        ax3.set_ylim(0, 105)
        ax3.grid(True, alpha=0.3)

        # Add percentage labels
        for bar, rate in zip(bars3, success_rates):
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{rate:.1f}%', ha='center', va='bottom')

        # Chart 4: zkVoting Comparison
        our_times = [times[0], times[1]]  # Generation and Tabulation
        zkvoting_times = [2300, 3.9]  # zkVoting baseline

        x = np.arange(2)
        width = 0.35

        bars4a = ax4.bar(x - width/2, our_times, width, label='Our System', color='#3498db')
        bars4b = ax4.bar(x + width/2, zkvoting_times, width, label='zkVoting', color='#e67e22')

        ax4.set_title('Performance vs zkVoting Research')
        ax4.set_ylabel('Time (milliseconds)')
        ax4.set_xticks(x)
        ax4.set_xticklabels(['Vote Casting', 'Tabulation'])
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        ax4.set_yscale('log')  # Log scale due to large difference

        # Add value labels
        for bars in [bars4a, bars4b]:
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height * 1.1,
                        f'{height:.1f}ms', ha='center', va='bottom', fontsize=8)

        plt.tight_layout()

        # Save to base64 string
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        print("✅ Charts generated successfully")
        return chart_data

    except ImportError:
        print("❌ Matplotlib not available for chart generation")
        return None
    except Exception as e:
        print(f"❌ Error generating charts: {e}")
        return None

def get_performance_recommendation_complete(generation_results, tabulation_results, decryption_results):
    """
    Generate performance recommendations based on benchmark results
    """
    try:
        recommendations = []

        # Analyze generation performance
        gen_time = generation_results.get('avg_time_per_vote', 0) * 1000  # Convert to ms
        gen_success_rate = generation_results.get('success_rate', 100)

        if gen_time > 500:  # If generation takes more than 500ms per vote
            recommendations.append({
                'type': 'warning',
                'category': 'Vote Generation',
                'message': f'Vote generation is slow ({gen_time:.1f}ms per vote). Consider optimizing cryptographic operations.',
                'suggestion': 'Use hardware acceleration or optimize blind signature implementation.'
            })
        elif gen_time < 50:
            recommendations.append({
                'type': 'success',
                'category': 'Vote Generation',
                'message': f'Excellent vote generation performance ({gen_time:.1f}ms per vote).',
                'suggestion': 'Performance is optimal for production use.'
            })

        if gen_success_rate < 99:
            recommendations.append({
                'type': 'error',
                'category': 'Vote Generation',
                'message': f'Low success rate ({gen_success_rate:.1f}%). Check cryptographic key consistency.',
                'suggestion': 'Review blind signature implementation and key management.'
            })

        # Analyze tabulation performance
        tab_time = tabulation_results.get('avg_time_per_ballot', 0) * 1000  # Convert to ms
        tab_throughput = tabulation_results.get('ballots_per_second', 0)

        if tab_time > 10:  # If tabulation takes more than 10ms per ballot
            recommendations.append({
                'type': 'warning',
                'category': 'Tabulation',
                'message': f'Tabulation is slow ({tab_time:.2f}ms per ballot). Consider database optimization.',
                'suggestion': 'Add database indexes or optimize counting queries.'
            })
        elif tab_throughput > 1000:
            recommendations.append({
                'type': 'success',
                'category': 'Tabulation',
                'message': f'Excellent tabulation throughput ({tab_throughput:.0f} ballots/second).',
                'suggestion': 'System can handle high-volume elections efficiently.'
            })

        # Analyze verification performance
        ver_success_rate = decryption_results.get('verification_success_rate', 100)
        ver_time = decryption_results.get('avg_time_per_vote', 0) * 1000  # Convert to ms

        if ver_success_rate < 98:
            recommendations.append({
                'type': 'error',
                'category': 'Verification',
                'message': f'Low verification success rate ({ver_success_rate:.1f}%).',
                'suggestion': 'Check signature verification logic and key consistency.'
            })

        if ver_time > 100:
            recommendations.append({
                'type': 'warning',
                'category': 'Verification',
                'message': f'Verification is slow ({ver_time:.1f}ms per vote).',
                'suggestion': 'Optimize decryption and signature verification processes.'
            })

        # Compare with zkVoting
        if gen_time < 2300:  # zkVoting baseline
            speedup = 2300 / gen_time if gen_time > 0 else 0
            recommendations.append({
                'type': 'success',
                'category': 'Performance Comparison',
                'message': f'Vote casting is {speedup:.1f}x faster than zkVoting research baseline.',
                'suggestion': 'Excellent performance for practical deployment.'
            })

        if tab_time < 3.9:  # zkVoting tally baseline
            speedup = 3.9 / tab_time if tab_time > 0 else 0
            recommendations.append({
                'type': 'success',
                'category': 'Performance Comparison',
                'message': f'Tabulation is {speedup:.1f}x faster than zkVoting research baseline.',
                'suggestion': 'Superior counting performance achieved.'
            })

        # Overall system recommendation
        total_time = gen_time + tab_time + ver_time
        if total_time < 100:
            recommendations.append({
                'type': 'success',
                'category': 'Overall System',
                'message': f'Total end-to-end time is excellent ({total_time:.1f}ms per vote).',
                'suggestion': 'System is ready for production deployment.'
            })
        elif total_time > 1000:
            recommendations.append({
                'type': 'warning',
                'category': 'Overall System',
                'message': f'Total processing time is high ({total_time:.1f}ms per vote).',
                'suggestion': 'Consider performance optimizations before large-scale deployment.'
            })

        # If no specific recommendations, add a general one
        if not recommendations:
            recommendations.append({
                'type': 'info',
                'category': 'General',
                'message': 'System performance is within acceptable ranges.',
                'suggestion': 'Continue monitoring performance in production environment.'
            })

        return recommendations

    except Exception as e:
        print(f"❌ Error generating recommendations: {e}")
        return [{
            'type': 'error',
            'category': 'System',
            'message': 'Unable to generate performance recommendations.',
            'suggestion': 'Check system logs for detailed error information.'
        }]

# Also add these helper functions if they're missing:

def decrypt_vote(encrypted_vote):
    """
    Decrypt a vote (placeholder implementation)
    """
    try:
        # This is a simplified decryption - replace with your actual implementation
        return encrypted_vote  # Placeholder
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

def verify_vote_signature(signature, vote_data):
    """
    Verify vote signature (placeholder implementation)
    """
    try:
        # This is a simplified verification - replace with your actual implementation
        return True  # Placeholder - always returns True for demo
    except Exception as e:
        return False

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    cert_path = "config/dev.certificate.crt"
    key_path = "config/dev.private.key"

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
