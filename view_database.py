#!/usr/bin/env python3
"""
Simple Database Viewer
Menampilkan isi database tanpa narasi
"""

import sqlite3

def view_blind_signature_db():
    conn = sqlite3.connect("voting_with_blind_signature.db")
    cursor = conn.cursor()

    print("=== BLIND SIGNATURE DATABASE ===")
    print("\nTabel: ballots")
    cursor.execute("SELECT * FROM ballots")
    results = cursor.fetchall()

    # Header
    cursor.execute("PRAGMA table_info(ballots)")
    columns = [col[1] for col in cursor.fetchall()]
    print(" | ".join(columns))
    print("-" * 80)

    # Data
    for row in results:
        print(" | ".join(str(col) for col in row))

    conn.close()

def view_non_blind_db():
    conn = sqlite3.connect("voting_without_blind_signature.db")
    cursor = conn.cursor()

    print("\n\n=== NON-BLIND SIGNATURE DATABASE ===")
    print("\nTabel: votes")
    cursor.execute("SELECT * FROM votes")
    results = cursor.fetchall()

    # Header
    cursor.execute("PRAGMA table_info(votes)")
    columns = [col[1] for col in cursor.fetchall()]
    print(" | ".join(columns))
    print("-" * 120)

    # Data
    for row in results:
        print(" | ".join(str(col) for col in row))

    conn.close()

def main():
    view_blind_signature_db()
    view_non_blind_db()

if __name__ == "__main__":
    main()
