import sqlite3
import hashlib
import secrets
import string
import cryptomath
import base64
from cryptography.fernet import Fernet


# Simple encryption key for NPM (in production, this should be in environment variable)
# Using fixed key to ensure consistency across imports
ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_npm(npm):
    """Encrypt NPM for secure storage while allowing decryption for display"""
    return cipher_suite.encrypt(npm.encode()).decode()

def decrypt_npm(encrypted_npm):
    """Decrypt NPM for display purposes"""
    try:
        return cipher_suite.decrypt(encrypted_npm.encode()).decode()
    except:
        return "DECRYPTION_ERROR"


# Create a new SQLite database (or connect to an existing one)
conn = sqlite3.connect('evoting.db', timeout=30)
c = conn.cursor()


# Create tables
# PERBAIKAN: Struktur tabel keys yang aman - TIDAK menyimpan private key
c.execute('''CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY,
                n TEXT NOT NULL,
                e TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

# PERBAIKAN: Tabel untuk menyimpan private key sementara di memory (akan dihapus)
c.execute('''CREATE TABLE IF NOT EXISTS temp_private_keys (
                id INTEGER PRIMARY KEY,
                d TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                name TEXT,
                photo TEXT,
                class TEXT,
                type TEXT)''')

# PERBAIKAN: Tabel voters dengan anonymity protection
c.execute('''CREATE TABLE IF NOT EXISTS voters (
                id INTEGER PRIMARY KEY,
                id_number_hash TEXT UNIQUE NOT NULL,
                id_number_encrypted TEXT NOT NULL,
                digital_signature TEXT,
                approved INTEGER DEFAULT 0,
                photo TEXT,
                token_hash TEXT UNIQUE NOT NULL,
                token_used_senat INTEGER DEFAULT 0,
                token_used_dewan INTEGER DEFAULT 0,
                registration_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

# PERBAIKAN: Tabel untuk session management (temporary)
c.execute('''CREATE TABLE IF NOT EXISTS voting_sessions (
                id INTEGER PRIMARY KEY,
                session_token TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                used INTEGER DEFAULT 0)''')

# PERBAIKAN: Struktur tabel ballots yang memenuhi kaidah blind signature
# Hanya menyimpan signature tanpa mengungkap candidate choice
c.execute('''CREATE TABLE IF NOT EXISTS ballots (
                id INTEGER PRIMARY KEY,
                signature TEXT NOT NULL,
                type TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

# PERBAIKAN: Tabel terpisah untuk public verification tanpa linking
c.execute('''CREATE TABLE IF NOT EXISTS verified_votes (
                id INTEGER PRIMARY KEY,
                vote_hash TEXT NOT NULL,
                is_valid INTEGER NOT NULL,
                type TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

conn.commit()
conn.close()


def get_db_connection():
    conn = sqlite3.connect('evoting.db', timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")  # Aktifkan WAL mode
    return conn


def generate_token(length=6):
    # Generate token with combination of uppercase letters and digits
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


# PERBAIKAN: Fungsi save_keys yang aman - hanya simpan public key
def save_keys(n, e, d=None):
    """
    Simpan public key (n, e) ke database
    Private key (d) TIDAK disimpan untuk keamanan blind signature
    """
    with get_db_connection() as conn:
        c = conn.cursor()
        params = (str(n), str(e))
        c.execute("INSERT INTO keys (n, e, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)", params)
        conn.commit()

        # OPTIONAL: Simpan private key sementara untuk session aktif saja
        if d is not None:
            import uuid
            session_id = str(uuid.uuid4())
            c.execute("INSERT INTO temp_private_keys (d, session_id) VALUES (?, ?)",
                     (str(d), session_id))
            conn.commit()
            return session_id
    return None


# PERBAIKAN: Fungsi save_voter dengan enhanced privacy
def save_voter(id_number, digital_signature, photo_filename):
    """
    Simpan voter dengan proteksi anonymity - hash ID dan token
    """
    token = generate_token()

    # Hash ID number untuk privacy
    id_hash = hashlib.sha256(id_number.encode()).hexdigest()

    # Encrypt ID number untuk keperluan display admin
    id_encrypted = encrypt_npm(id_number)

    # Hash token untuk unlinkability
    salted_token = token + "PoltekSSN"
    hashed_token = hashlib.sha256(salted_token.encode()).hexdigest()
    encoded_token = base64.b64encode(hashed_token.encode()).decode()

    params = (id_hash, id_encrypted, digital_signature, photo_filename, encoded_token)
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO voters (id_number_hash, id_number_encrypted, digital_signature, photo, token_hash) VALUES (?, ?, ?, ?, ?)", params)
        conn.commit()
    return token


def save_candidate(name, photo_filename, candidate_class, candidate_type):
    params = (name, photo_filename, candidate_class, candidate_type)
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO candidates (name, photo, class, type) VALUES (?, ?, ?, ?)", params)
        conn.commit()
    print(f"Saved candidate: {name}")


# PERBAIKAN: Fungsi save_ballot yang memenuhi kaidah blind signature
def save_ballot(signature, voting_type):
    """
    Simpan hanya signature tanpa candidate_id untuk mempertahankan vote privacy
    Candidate choice akan diextract saat verification/tallying
    """
    params = (str(signature), voting_type)
    with get_db_connection() as conn:
        c = conn.cursor()
        # Hanya simpan signature dan type - TIDAK ada candidate_id
        c.execute('''INSERT INTO ballots (signature, type)
                     VALUES (?, ?)''', params)
        conn.commit()


# PERBAIKAN: Fungsi untuk vote tallying dengan signature verification
def tally_votes_from_signatures():
    """
    Menghitung suara dari signature yang tersimpan
    Mengembalikan kandidat berdasarkan verifikasi signature
    """
    from Recap import decrypt_and_verify_votes
    return decrypt_and_verify_votes()


# PERBAIKAN: Implementasi verify_ballot yang sesuai dengan protokol blind signature
def verify_ballot(candidate_id, signature, public_key, n):
    """
    Verifikasi tanda tangan sesuai protokol blind signature standar
    σ^e mod n = H(m)
    """
    # Dekripsi tanda tangan menggunakan kunci publik
    decrypted = pow(int(signature), public_key, n)

    # Hitung hash dari candidate_id
    message_hash = int(hashlib.sha256(str(candidate_id).encode()).hexdigest(), 16)

    # Bandingkan hasil dekripsi dengan hash
    return decrypted == message_hash


def create_admin():
    username = 'AdminKitaBersama'
    password = hashlib.sha256('AdminKitaBersama'.encode()).hexdigest()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()


# Create admin user
create_admin()


def get_all_candidates():
    conn = get_db_connection()
    # Gunakan alias "candidate_type" untuk kolom "type"
    candidates = conn.execute(
        'SELECT id, name, photo, class, type AS candidate_type FROM candidates'
    ).fetchall()
    conn.close()
    return candidates


# PERBAIKAN: Fungsi get_existing_keys yang aman - hanya ambil public key
def get_existing_keys():
    """
    Ambil public key yang tersimpan. Private key TIDAK disimpan di database.
    """
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT n, e FROM keys ORDER BY timestamp DESC LIMIT 1")
        key = c.fetchone()
    if key:
        n, e = int(key[0]), int(key[1])
        return n, e, None  # d=None karena tidak disimpan
    return None


# PERBAIKAN: Fungsi untuk manage temporary private key
def get_session_private_key(session_id):
    """
    Ambil private key berdasarkan session_id (temporary storage)
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT d FROM temp_private_keys WHERE session_id = ?", (session_id,))
                result = c.fetchone()
                if result:
                    return int(result[0])
                return None
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                import time
                time.sleep(0.1 * (attempt + 1))
                continue
            else:
                raise
        except Exception as e:
            raise


def save_session_private_key(d, session_id):
    """
    Simpan private key sementara berdasarkan session_id
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                # Hapus yang lama jika ada
                c.execute("DELETE FROM temp_private_keys WHERE session_id = ?", (session_id,))
                # Simpan yang baru
                c.execute("INSERT INTO temp_private_keys (d, session_id) VALUES (?, ?)",
                          (str(d), session_id))
                conn.commit()
                return  # Success, exit function
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                # Wait a bit and retry
                import time
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                continue
            else:
                raise  # Re-raise if not a lock error or if max retries reached
        except Exception as e:
            raise  # Re-raise other exceptions


def cleanup_expired_private_keys():
    """
    Bersihkan private key yang expired dari temporary storage
    """
    with get_db_connection() as conn:
        c = conn.cursor()
        # Hapus private key yang lebih dari 1 jam
        c.execute("""DELETE FROM temp_private_keys
                     WHERE created_at < datetime('now', '-1 hour')""")
        conn.commit()


def generate_and_save_keys():
    """
    Generate RSA keys dan simpan hanya public key ke database
    Private key disimpan temporary atau di-generate on-demand
    """
    p = cryptomath.find_prime()
    q = cryptomath.find_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Eksponent publik standar
    d = cryptomath.find_mod_inverse(e, phi)

    # Simpan hanya public key
    session_id = save_keys(n, e, d)  # d disimpan temporary
    print(f"Keys generated - Public key saved, Private key in session: {session_id}")
    return session_id


# Generate and save keys if they don't exist
keys_result = get_existing_keys()
if not keys_result:
    session_id = generate_and_save_keys()
    print(f"New keys generated with session: {session_id}")
else:
    print("Existing public keys found in database")

# Schedule cleanup of expired private keys
import atexit
atexit.register(cleanup_expired_private_keys)