import sqlite3
import hashlib
import BlindSig as bs
from key_manager import get_global_keys, verify_with_global_key
from createdb import get_active_key

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

    # PERBAIKAN: Gunakan key management yang proper dengan key references
    print("DEBUG Recap: Starting vote tallying with key-aware verification")

    # Ambil semua ballots dengan key reference-nya
    c.execute("""
        SELECT b.signature, b.type, b.key_id, k.n, k.e
        FROM ballots b
        JOIN keys k ON b.key_id = k.id
        ORDER BY b.timestamp
    """)
    ballots_with_keys = c.fetchall()

    # Jika tidak ada data dari join, fallback ke metode lama
    if not ballots_with_keys:
        print("DEBUG Recap: No ballots with key references found, trying legacy method")
        c.execute("SELECT signature, type FROM ballots")
        legacy_ballots = c.fetchall()

        if legacy_ballots:
            # Gunakan global key untuk legacy ballots
            keys = get_global_keys()
            n, public_key = keys['n'], keys['e']
            ballots_with_keys = [(sig, typ, None, str(n), str(public_key)) for sig, typ in legacy_ballots]
        else:
            print("DEBUG Recap: No ballots found in database")
            conn.close()
            return [], {'senat': {}, 'demus': {}}, {'senat': [], 'demus': []}

    # Retrieve candidate names and types
    c.execute("SELECT id, name, type FROM candidates")
    candidates = c.fetchall()
    candidate_dict = {candidate[0]: (candidate[1], candidate[2]) for candidate in candidates}

    # Close the database connection
    conn.close()

    # PERBAIKAN: Pre-calculate message hashes untuk semua kandidat
    candidate_hashes = {}
    for candidate_id, (candidate_name, candidate_type) in candidate_dict.items():
        message_hash = hashlib.sha256(str(candidate_id).encode()).hexdigest()
        message_hash_int = int(message_hash, 16)
        candidate_hashes[candidate_id] = message_hash_int

    # Initialize vote counts for senat and demus
    vote_counts = {'senat': {}, 'demus': {}}
    verified_ballots = []

    print(f"DEBUG Recap: Processing {len(ballots_with_keys)} ballots with {len(candidates)} candidates")
    processed_ballots = 0

    # PERBAIKAN: Verify each ballot dengan key yang tepat
    for ballot_data in ballots_with_keys:
        signature, ballot_type, key_id, n_str, e_str = ballot_data
        processed_ballots += 1

        if processed_ballots % 10 == 0:  # Progress indicator
            print(f"DEBUG Recap: Processed {processed_ballots}/{len(ballots_with_keys)} ballots")

        try:
            # Convert key strings to integers
            n = int(n_str)
            public_key = int(e_str)

            # Pre-calculate signature decryption dengan key yang tepat
            decrypted_signature = pow(int(signature), public_key, n)

            # PERBAIKAN: Coba cocokkan dengan hash kandidat yang sudah di-precompute
            for candidate_id, (candidate_name, candidate_type) in candidate_dict.items():
                if candidate_type == ballot_type:  # Hanya cek kandidat dengan tipe yang sesuai
                    expected_hash = candidate_hashes[candidate_id]

                    # Adjust hash jika melebihi modulus
                    if expected_hash >= n:
                        expected_hash = expected_hash % n

                    if decrypted_signature == expected_hash:
                        verified_ballots.append((candidate_name, candidate_type))

                        if candidate_name in vote_counts[candidate_type]:
                            vote_counts[candidate_type][candidate_name] += 1
                        else:
                            vote_counts[candidate_type][candidate_name] = 1

                        print(f"DEBUG Recap: Vote verified for {candidate_name} ({candidate_type}) using key_id={key_id}")
                        # Break karena signature sudah terverifikasi untuk kandidat ini
                        break
        except (ValueError, TypeError, OverflowError) as e:
            print(f"DEBUG Recap: Error processing ballot signature {signature}: {e}")
            continue

    # Ensure all candidates are included in the vote counts, even if they have 0 votes
    all_candidates = {'senat': [], 'demus': []}
    for candidate_id, (candidate_name, candidate_type) in candidate_dict.items():
        all_candidates[candidate_type].append({'id': candidate_id, 'name': candidate_name})
        if candidate_name not in vote_counts[candidate_type]:
            vote_counts[candidate_type][candidate_name] = 0

    print(f"DEBUG Recap: Completed processing. Verified {len(verified_ballots)} ballots")
    return verified_ballots, vote_counts, all_candidates
# Run the functions
if __name__ == "__main__":
    print_database_contents()
    recap_votes()