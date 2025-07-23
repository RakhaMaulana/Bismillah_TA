import sqlite3
import hashlib
import BlindSig as bs

DATABASE_NAME = 'evoting.db'


def fetch_all_keys():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("SELECT n, e FROM keys")
    keys = c.fetchall()
    conn.close()
    return [(int(key[0]), int(key[1])) for key in keys]


def verify_signature(candidate_id, signature, public_key, n):
    """
    Verifikasi tanda tangan sesuai protokol blind signature standar
    σ^e mod n = H(m)
    """
    try:
        # Decrypt the signature using the public key
        decrypted = pow(int(signature), public_key, n)

        # Calculate the hash of the candidate_id (same as in app.py)
        message_hash = hashlib.sha256(str(candidate_id).encode()).hexdigest()
        calculated_hash = int(message_hash, 16)

        # PERBAIKAN: Pastikan hash tidak lebih besar dari modulus (sama seperti di app.py)
        if calculated_hash >= n:
            calculated_hash = calculated_hash % n

        # Compare the decrypted signature with the calculated hash
        return decrypted == calculated_hash
    except (ValueError, TypeError, OverflowError):
        return False


def print_database_contents():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()

    # Print keys table
    c.execute("SELECT * FROM keys")
    keys = c.fetchall()
    c.execute("SELECT * FROM voters")
    voters = c.fetchall()
    c.execute("SELECT * FROM ballots")
    ballots = c.fetchall()

    conn.close()


def recap_votes():
    # Connect to the database
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()

    # Retrieve all keys from the database
    keys = fetch_all_keys()

    # PERBAIKAN: Retrieve ballots tanpa candidate_id (sesuai blind signature)
    # Hanya ambil signature dan type untuk verifikasi
    c.execute("SELECT signature, type FROM ballots")
    ballots = c.fetchall()

    # Retrieve candidate names and types
    c.execute("SELECT id, name, type FROM candidates")
    candidates = c.fetchall()
    candidate_dict = {candidate[0]: (candidate[1], candidate[2]) for candidate in candidates}

    # Close the database connection
    conn.close()

    # Initialize vote counts for senat and demus
    vote_counts = {'senat': {}, 'demus': {}}
    verified_ballots = []

    # PERBAIKAN: Verify each ballot dengan pendekatan blind signature yang benar
    # Karena candidate_id tidak disimpan, kita perlu mencoba verifikasi terhadap setiap kandidat
    for ballot in ballots:
        signature, ballot_type = ballot

        # Coba verifikasi signature terhadap setiap kandidat dengan tipe yang sesuai
        for candidate_id, (candidate_name, candidate_type) in candidate_dict.items():
            if candidate_type == ballot_type:  # Hanya cek kandidat dengan tipe yang sesuai
                for n, public_key in keys:
                    # PERBAIKAN: Gunakan fungsi verify_signature dari BlindSig.py
                    if bs.verify_signature(str(candidate_id), signature, public_key, n):
                        verified_ballots.append((candidate_name, candidate_type))

                        if candidate_name in vote_counts[candidate_type]:
                            vote_counts[candidate_type][candidate_name] += 1
                        else:
                            vote_counts[candidate_type][candidate_name] = 1

                        # Break kedua loop karena signature sudah terverifikasi
                        break
                else:
                    continue  # Continue outer loop jika tidak ada key yang cocok
                break  # Break jika signature sudah terverifikasi untuk kandidat ini

    # Ensure all candidates are included in the vote counts, even if they have 0 votes
    all_candidates = {'senat': [], 'demus': []}
    for candidate_id, (candidate_name, candidate_type) in candidate_dict.items():
        all_candidates[candidate_type].append({'id': candidate_id, 'name': candidate_name})
        if candidate_name not in vote_counts[candidate_type]:
            vote_counts[candidate_type][candidate_name] = 0

    return verified_ballots, vote_counts, all_candidates


# Run the functions
if __name__ == "__main__":
    print_database_contents()
    recap_votes()