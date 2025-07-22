import sqlite3

conn = sqlite3.connect('evoting.db')
c = conn.cursor()

print('Tables in database:')
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
for table in tables:
    print(f'- {table[0]}')

print('\nBallots table structure:')
try:
    c.execute('PRAGMA table_info(ballots)')
    columns = c.fetchall()
    for col in columns:
        print(f'  {col[1]} {col[2]}')
except:
    print('  Ballots table not found')

print('\nRecent ballots:')
try:
    c.execute('SELECT * FROM ballots ORDER BY rowid DESC LIMIT 5')
    ballots = c.fetchall()
    for ballot in ballots:
        print(f'  {ballot}')
    if not ballots:
        print('  No ballots found')
except Exception as e:
    print(f'  Error: {e}')

print('\nVoters with tokens:')
try:
    c.execute('SELECT id_number, approved, token_used_senat, token_used_dewan FROM voters LIMIT 3')
    voters = c.fetchall()
    for voter in voters:
        print(f'  ID: {voter[0]}, Approved: {voter[1]}, Senat: {voter[2]}, Dewan: {voter[3]}')
except Exception as e:
    print(f'  Error: {e}')

conn.close()
