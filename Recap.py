import sqlite3
import hashlib

def fetch_all_keys():
    conn = sqlite3.connect('evoting.db')
    c = conn.cursor()
    c.execute("SELECT n, e FROM keys")
    keys = c.fetchall()
    conn.close()
    return [(int(key[0]), int(key[1])) for key in keys]

def verify_vote(concatenated_message, unblinded_signature, public_key, n):
    # Decrypt the signed message using the public key
    decrypted_message = pow(int(unblinded_signature), public_key, n)

    # Calculate the hash of the concatenated message
    calculated_hash = int(hashlib.sha256(concatenated_message.encode('utf-8')).hexdigest(), 16)

    # Debugging statements
    print(f"Decrypted message: {decrypted_message}")
    print(f"Calculated hash: {calculated_hash}")

    # Compare the decrypted message with the calculated hash
    return decrypted_message == calculated_hash

def print_database_contents():
    conn = sqlite3.connect('evoting.db')
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
    conn = sqlite3.connect('evoting.db')
    c = conn.cursor()

    # Retrieve all keys from the database
    keys = fetch_all_keys()

    # Retrieve all ballots from the database
    c.execute("SELECT concatenated_message, unblinded_signature FROM ballots")
    ballots = c.fetchall()

    # Close the database connection
    conn.close()

    # Initialize vote counts dynamically
    vote_counts = {}

    # Verify each ballot and count the votes
    for ballot in ballots:
        concatenated_message, unblinded_signature = ballot
        for n, public_key in keys:
            if verify_vote(concatenated_message, unblinded_signature, public_key, n):
                vote = concatenated_message[0]  # Assuming the vote is the first character of concatenated_message
                if vote in vote_counts:
                    vote_counts[vote] += 1
                else:
                    vote_counts[vote] = 1
                print(f"Vote for candidate {vote} verified and counted.")
                break  # Stop checking other keys if the vote is verified
            else:
                print(f"Vote for candidate {concatenated_message[0]} not verified with key (n={n}, e={public_key}).")

    # Print the vote counts
    print("Final vote counts:")
    for candidate, count in vote_counts.items():
        print(f"Candidate {candidate}: {count} votes")

# Run the functions
if __name__ == "__main__":
    print_database_contents()
    recap_votes()