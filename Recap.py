import sqlite3
import hashlib

DATABASE_NAME = 'evoting.db'


def fetch_all_keys():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("SELECT n, e FROM keys")
    keys = c.fetchall()
    conn.close()
    return [(int(key[0]), int(key[1])) for key in keys]


def verify_vote(concatenated_message, unblinded_signature, public_key, n):
    # Decrypt the signed message using the public key
    decrypted_message = pow(int(unblinded_signature), public_key, n)

    # Calculate the hash of the concatenated message
    calculated_hash = int(hashlib.sha256(
        concatenated_message.encode('utf-8')).hexdigest(), 16)

    # Compare the decrypted message with the calculated hash
    return decrypted_message == calculated_hash


def print_database_contents():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()

    # Print keys table
    print("Keys Table:")
    c.execute("SELECT * FROM keys")
    keys = c.fetchall()
    for key in keys:
        print(key)
    print()

    # Print voters table
    print("Voters Table:")
    c.execute("SELECT * FROM voters")
    voters = c.fetchall()
    for voter in voters:
        print(voter)
    print()

    # Print ballots table
    print("Ballots Table:")
    c.execute("SELECT * FROM ballots")
    ballots = c.fetchall()
    for ballot in ballots:
        print(ballot)
    print()

    conn.close()


def recap_votes():
    # Connect to the database
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()

    # Retrieve all keys from the database
    keys = fetch_all_keys()

    # Retrieve all ballots from the database
    c.execute("SELECT concatenated_message, unblinded_signature FROM ballots")
    ballots = c.fetchall()

    # Retrieve candidate names and types
    c.execute("SELECT id, name, type FROM candidates")
    candidates = c.fetchall()
    candidate_dict = {str(candidate[0]): (candidate[1], candidate[2]) for candidate in candidates}

    # Close the database connection
    conn.close()

    # Initialize vote counts for senat and demus
    vote_counts = {'senat': {}, 'demus': {}}
    verified_ballots = []

    # Verify each ballot and count the votes
    for ballot in ballots:
        concatenated_message, unblinded_signature = ballot
        for n, public_key in keys:
            if verify_vote(concatenated_message, unblinded_signature, public_key, n):
                candidate_id = concatenated_message[0]
                candidate_name, candidate_type = candidate_dict[candidate_id]
                verified_ballots.append((candidate_name, candidate_type))
                if candidate_name in vote_counts[candidate_type]:
                    vote_counts[candidate_type][candidate_name] += 1
                else:
                    vote_counts[candidate_type][candidate_name] = 1
                break  # Stop checking other keys if the vote is verified

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