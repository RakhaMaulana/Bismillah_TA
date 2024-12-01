import sqlite3
import hashlib
import random
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import BlindSig as bs
import cryptomath
import os
import base64

# Create a new SQLite database (or connect to an existing one)
conn = sqlite3.connect('evoting.db')
c = conn.cursor()

# Drop the keys table if it exists
c.execute("DROP TABLE IF EXISTS keys")

# Drop the whitelisted_ips table if it exists
c.execute("DROP TABLE IF EXISTS whitelisted_ips")

# Create tables
c.execute('''CREATE TABLE keys (
                id INTEGER PRIMARY KEY,
                n TEXT,
                e TEXT,
                d TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                name TEXT,
                photo TEXT,
                class TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS voters (
                id INTEGER PRIMARY KEY,
                id_number TEXT,
                digital_signature TEXT,
                approved INTEGER DEFAULT 0,
                photo TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS ballots (
                id INTEGER PRIMARY KEY,
                x TEXT,
                concatenated_message TEXT,
                message_hash TEXT,
                blinded_message TEXT,
                signed_blind_message TEXT,
                unblinded_signature TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS whitelisted_ips (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE)''')

conn.commit()

def get_db_connection():
    conn = sqlite3.connect('evoting.db')
    conn.row_factory = sqlite3.Row
    return conn

def save_keys(n, e, d):
    conn = get_db_connection()
    c = conn.cursor()
    params = (str(n), str(e), str(d))
    c.execute("INSERT INTO keys (n, e, d, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", params)
    conn.commit()
    conn.close()

def save_voter(id_number, digital_signature, photo_filename):
    conn = get_db_connection()
    c = conn.cursor()
    params = (id_number, digital_signature, photo_filename)
    c.execute("INSERT INTO voters (id_number, digital_signature, photo) VALUES (?, ?, ?)", params)
    conn.commit()
    conn.close()
    print(f"Saved voter: {id_number}")

def save_candidate(name, photo_filename, candidate_class):
    conn = get_db_connection()
    c = conn.cursor()
    params = (name, photo_filename, candidate_class)
    c.execute("INSERT INTO candidates (name, photo, class) VALUES (?, ?, ?)", params)
    conn.commit()
    conn.close()
    print(f"Saved candidate: {name}")

def save_ballot(x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature):
    conn = get_db_connection()
    c = conn.cursor()
    params = (str(x), concatenated_message, str(message_hash), str(blinded_message), str(signed_blind_message), str(unblinded_signature))
    c.execute('''INSERT INTO ballots (x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature)
                 VALUES (?, ?, ?, ?, ?, ?)''', params)
    conn.commit()
    conn.close()

def verify_ballot(id_number, public_key, n):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT digital_signature FROM voters WHERE id_number=?", (id_number,))
    voter = c.fetchone()
    conn.close()
    if voter:
        digital_signature = voter[0]
        decrypted_message = pow(int(digital_signature), public_key, n)
        if decrypted_message == int(id_number):
            print("Vote is valid")
        else:
            print("Vote is invalid")
    else:
        print("Voter not found")

def create_admin():
    conn = get_db_connection()
    c = conn.cursor()
    username = 'AdminKitaBersama'
    password = hashlib.sha256('AdminKitaBersama'.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def create_local():
    conn = get_db_connection()
    c = conn.cursor()
    ip_address = "127.0.0.1"
    c.execute("INSERT INTO whitelisted_ips (ip_address) VALUES (?)", (ip_address,))
    conn.commit()
    conn.close()
    print("Localhost whitelisted")

# Create admin user
create_admin()
create_local()

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

def generate_and_save_keys():
    p = cryptomath.findPrime()
    q = cryptomath.findPrime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = cryptomath.findModInverse(e, phi)
    save_keys(n, e, d)
    print("Keys generated and saved")

# Generate and save keys if they don't exist
if not get_existing_keys():
    generate_and_save_keys()

app = Flask(__name__)
app.secret_key = 'AdminKitaBersama'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/manage_ips', methods=['GET', 'POST'])
def manage_ips():
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM whitelisted_ips WHERE ip_address = ?", (ip_address,))
        result = c.fetchone()
        if result:
            flash('IP address already exists')
        else:
            c.execute("INSERT INTO whitelisted_ips (ip_address) VALUES (?)", (ip_address,))
            conn.commit()
            flash('IP address added successfully')
        conn.close()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM whitelisted_ips")
    ips = c.fetchall()
    conn.close()
    return render_template('manage_ips.html', ips=ips)

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if not is_ip_whitelisted(request.remote_addr):
        abort(403)  # Forbidden

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
            n, e, d = existing_keys
        else:
            flash('No keys found')
            return redirect(url_for('vote'))

        x = random.randint(1, n)
        concat_message = str(candidate_id) + str(x)
        message_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        message_hash = int(message_hash, 16)
        voter = bs.Voter(n, "y")
        blindMessage = voter.blindMessage(message_hash, n, e)
        signer = bs.Signer()
        signedBlindMessage = signer.signMessage(blindMessage, voter.getEligibility())
        signedMessage = voter.unwrapSignature(signedBlindMessage, n)
        save_ballot(x, concat_message, message_hash, str(blindMessage), str(signedBlindMessage), str(signedMessage))
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