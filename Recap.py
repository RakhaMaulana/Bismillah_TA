import sqlite3
import hashlib

def fetch_public_key():
    conn = sqlite3.connect('evoting.db')
    c = conn.cursor()
    c.execute("SELECT n, e FROM keys ORDER BY id DESC LIMIT 1")
    key = c.fetchone()
    conn.close()
    if key:
        n, e = int(key[0]), int(key[1])
        return n, e
    else:
        raise ValueError("Public key not found in the database")

def verify_vote(concatenated_message, unblinded_signature, public_key, n):
    # Decrypt the signed message using the public key
    decrypted_message = pow(int(unblinded_signature), public_key, n)

    # Calculate the hash of the concatenated message
    calculated_hash = int(hashlib.sha256(concatenated_message.encode('utf-8')).hexdigest(), 16)

    # Compare the decrypted message with the calculated hash
    return decrypted_message == calculated_hash

def count_votes():
    # Connect to the database
    conn = sqlite3.connect('evoting.db')
    c = conn.cursor()

    # Retrieve the public key and n from the database
    n, public_key = fetch_public_key()

    # Retrieve all ballots from the database
    c.execute("SELECT concatenated_message, unblinded_signature FROM ballots")
    ballots = c.fetchall()

    # Initialize vote counts dynamically
    vote_counts = {}

    # Verify each ballot and count the votes
    for ballot in ballots:
        concatenated_message, unblinded_signature = ballot
        if verify_vote(concatenated_message, unblinded_signature, public_key, n):
            vote = concatenated_message[0]
            if vote in vote_counts:
                vote_counts[vote] += 1
            else:
                vote_counts[vote] = 1

    conn.close()

    # Print the vote counts
    for candidate, count in vote_counts.items():
        print(f"Candidate {candidate}: {count} votes")

# Count and print the votes
count_votes()