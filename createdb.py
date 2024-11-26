import sqlite3

# Create a new SQLite database (or connect to an existing one)
conn = sqlite3.connect('evoting.db')
c = conn.cursor()

# Create tables
c.execute('''CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY,
                n TEXT,
                e TEXT,
                d TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS voters (
                id INTEGER PRIMARY KEY,
                idNumber_hash TEXT,
                digital_signature TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS ballots (
                id INTEGER PRIMARY KEY,
                x TEXT,
                concatenated_message TEXT,
                message_hash TEXT,
                blinded_message TEXT,
                signed_blind_message TEXT,
                unblinded_signature TEXT)''')

conn.commit()

def save_keys(n, e, d):
    c.execute("INSERT INTO keys (n, e, d) VALUES (?, ?, ?)", (str(n), str(e), str(d)))
    conn.commit()

def save_voter(idNumber_hash, digital_signature):
    c.execute("INSERT INTO voters (idNumber_hash, digital_signature) VALUES (?, ?)", (str(idNumber_hash), str(digital_signature)))
    conn.commit()

def save_ballot(x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature):
    c.execute("INSERT INTO ballots (x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature) VALUES (?, ?, ?, ?, ?, ?)",
              (str(x), concatenated_message, str(message_hash), str(blinded_message), str(signed_blind_message), str(unblinded_signature)))
    conn.commit()

def verify_ballot(idNumber_hash, public_key, n):
    c.execute("SELECT digital_signature FROM voters WHERE idNumber_hash=?", (str(idNumber_hash),))
    voter = c.fetchone()
    if voter:
        digital_signature = voter[0]
        decrypted_message = pow(int(digital_signature), public_key, n)
        if decrypted_message == int(idNumber_hash):
            print("Vote is valid")
        else:
            print("Vote is invalid")
    else:
        print("Voter not found")