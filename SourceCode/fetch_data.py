import sqlite3

# Create a new SQLite database (or connect to an existing one)
conn = sqlite3.connect('evoting.db')
c = conn.cursor()

def fetch_keys():
    c.execute("SELECT * FROM keys")
    return c.fetchall()

def fetch_voters():
    c.execute("SELECT * FROM voters")
    return c.fetchall()

def fetch_ballots():
    c.execute("SELECT * FROM ballots")
    return c.fetchall()

# Fetch and print keys
keys = fetch_keys()
print("Keys:")
for key in keys:
    print(key)

# Fetch and print voters
voters = fetch_voters()
print("\nVoters:")
for voter in voters:
    print(voter)

# Fetch and print ballots
ballots = fetch_ballots()
print("\nBallots:")
for ballot in ballots:
    print(ballot)