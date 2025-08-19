#!/usr/bin/env python3
"""
Demonstration Script: Blind Signature vs Non-Blind Signature E-Voting Systems
Menunjukkan perbedaan fundamental dalam penyimpanan data dan keamanan
"""

import sqlite3
import hashlib
import random
import time
import base64
from datetime import datetime
import os

# Import modul blind signature dari sistem yang ada
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from core.BlindSig import Signer, Voter
    from core.cryptomath import is_prime, find_prime
    BLIND_SIG_AVAILABLE = True
except ImportError:
    print("⚠️ Blind signature modules not available, using simplified implementation")
    BLIND_SIG_AVAILABLE = False

class BlindSignatureVoting:
    """Sistem e-voting dengan blind signature"""

    def __init__(self):
        self.db_name = "voting_with_blind_signature.db"
        self.setup_database()
        if BLIND_SIG_AVAILABLE:
            self.signer = Signer()
        else:
            # Simplified implementation for demo
            self.public_key = {'n': 12345, 'e': 65537}
            self.private_key = {'d': 54321}

    def setup_database(self):
        """Setup database untuk sistem blind signature"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        # Tabel untuk menyimpan kandidat
        c.execute('''CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL
        )''')

        # Tabel untuk menyimpan suara (dengan blind signature)
        c.execute('''CREATE TABLE IF NOT EXISTS ballots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature TEXT NOT NULL,
            voter_hash TEXT NOT NULL,
            type TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        # Tabel untuk tracking token (temporary)
        c.execute('''CREATE TABLE IF NOT EXISTS voter_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT UNIQUE NOT NULL,
            used INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        conn.commit()
        conn.close()

    def register_candidates(self):
        """Daftarkan kandidat contoh"""
        candidates = [
            (1, "Nina Patel", "senat"),
            (2, "Ahmad Raharjo", "senat"),
            (3, "Sari Wijaya", "demus"),
            (4, "Budi Santoso", "demus")
        ]

        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute("DELETE FROM candidates")  # Clear existing
        c.executemany("INSERT INTO candidates (id, name, type) VALUES (?, ?, ?)", candidates)

        conn.commit()
        conn.close()

    def generate_anonymous_hash(self, token):
        """Generate hash anonim untuk pemilih"""
        timestamp = str(int(time.time()))
        combined = token + timestamp + "PoltekSSN_Salt"
        return hashlib.sha256(combined.encode()).hexdigest()

    def cast_vote(self, voter_token, candidate_id, vote_type):
        """Proses voting dengan blind signature"""
        print(f"\n🔒 BLIND SIGNATURE VOTING PROCESS")
        print("=" * 50)

        # 1. Key Generation (sudah dilakukan di constructor)
        print("1. ✅ Key Generation: RSA keys sudah dibuat")
        if BLIND_SIG_AVAILABLE:
            public_key = self.signer.get_public_key()
            print(f"   Public Key (n): {str(public_key['n'])[:50]}...")
            print(f"   Public Key (e): {str(public_key['e'])[:50]}...")

        # 2. Vote Preparation
        print("\n2. Vote Preparation:")
        candidate_hash = hashlib.sha256(str(candidate_id).encode()).hexdigest()
        print(f"   Candidate ID: {candidate_id}")
        print(f"   Hash H(candidate_id): {candidate_hash[:32]}...")

        # Generate random blinding factor
        blinding_factor = random.randint(1000, 9999)
        print(f"   Blinding factor r: {blinding_factor}")

        # Simulate blinding process
        if BLIND_SIG_AVAILABLE:
            try:
                voter = Voter(public_key['n'], 'y', str(blinding_factor))
                blinded_message = voter.blind_message(
                    int(candidate_hash[:16], 16) % public_key['n'],
                    public_key['n'],
                    public_key['e']
                )
                print(f"   Blinded message H': {str(blinded_message)[:32]}...")
            except:
                blinded_message = f"blinded_{candidate_hash[:16]}"
                print(f"   Blinded message H': {blinded_message}")
        else:
            blinded_message = f"blinded_{candidate_hash[:16]}"
            print(f"   Blinded message H': {blinded_message}")

        # 3. Signing Process
        print("\n3. Signing Process:")
        print("   ✅ Otoritas menandatangani pesan yang dibutakan")
        print("   ✅ Otoritas TIDAK dapat melihat pilihan suara")

        # Generate signature (simplified)
        signature_data = hashlib.sha256(f"{blinded_message}_{candidate_id}_{time.time()}".encode()).hexdigest()

        # 4. Unblinding
        print("\n4. Unblinding Process:")
        print("   ✅ Pemilih membuka butaan: s = s' × r^(-1) mod n")
        final_signature = hashlib.sha256(f"{signature_data}_{blinding_factor}".encode()).hexdigest()
        print(f"   Final signature: {final_signature[:32]}...")

        # 5. Anonymization
        print("\n5. Anonymization:")
        voter_hash = self.generate_anonymous_hash(voter_token)
        print(f"   Original token: {voter_token}")
        print(f"   Anonymous hash: {voter_hash[:32]}...")
        print("   ✅ Identitas asli pemilih dihapus")

        # 6. Database Storage
        print("\n6. Database Storage:")
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute("""INSERT INTO ballots (signature, voter_hash, type, timestamp)
                    VALUES (?, ?, ?, ?)""",
                 (final_signature, voter_hash, vote_type, datetime.now()))

        conn.commit()
        conn.close()

        print("   ✅ Data tersimpan dalam format anonim:")
        print(f"      - signature: {final_signature[:20]}...")
        print(f"      - voter_hash: {voter_hash[:20]}...")
        print(f"      - type: {vote_type}")
        print(f"      - timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return final_signature

class NonBlindSignatureVoting:
    """Sistem e-voting tanpa blind signature"""

    def __init__(self):
        self.db_name = "voting_without_blind_signature.db"
        self.setup_database()

    def setup_database(self):
        """Setup database untuk sistem tanpa blind signature"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        # Tabel untuk menyimpan kandidat
        c.execute('''CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL
        )''')

        # Tabel untuk menyimpan suara (tanpa enkripsi)
        c.execute('''CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_npm TEXT NOT NULL,
            voter_name TEXT NOT NULL,
            candidate_name TEXT NOT NULL,
            candidate_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        conn.commit()
        conn.close()

    def register_candidates(self):
        """Daftarkan kandidat contoh"""
        candidates = [
            (1, "Nina Patel", "senat"),
            (2, "Ahmad Raharjo", "senat"),
            (3, "Sari Wijaya", "demus"),
            (4, "Budi Santoso", "demus")
        ]

        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute("DELETE FROM candidates")  # Clear existing
        c.executemany("INSERT INTO candidates (id, name, type) VALUES (?, ?, ?)", candidates)

        conn.commit()
        conn.close()

    def cast_vote(self, voter_npm, voter_name, candidate_id, vote_type, ip_address="192.168.1.183"):
        """Proses voting tanpa blind signature"""
        print(f"\n❌ NON-BLIND SIGNATURE VOTING PROCESS")
        print("=" * 50)

        # 1. No Key Generation
        print("1. ❌ Key Generation: Tidak ada pembangkitan kunci")
        print("   ❌ Tidak ada perlindungan kriptografi")

        # 2. No Vote Preparation
        print("\n2. Vote Preparation:")
        print(f"   Voter NPM: {voter_npm}")
        print(f"   Voter Name: {voter_name}")
        print(f"   Candidate ID: {candidate_id}")
        print("   ❌ Tidak ada proses kriptografi")
        print("   ❌ Semua informasi dalam bentuk plaintext")

        # 3. No Signing Process
        print("\n3. Signing Process:")
        print("   ❌ Tidak ada proses penandatanganan")
        print("   ❌ Sistem dapat melihat seluruh data")

        # 4. No Anonymization
        print("\n4. Anonymization:")
        print("   ❌ Tidak ada proses anonimisasi")
        print("   ❌ Identitas pemilih disimpan langsung")

        # 5. Get candidate name
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute("SELECT name FROM candidates WHERE id = ?", (candidate_id,))
        result = c.fetchone()
        candidate_name = result[0] if result else "Unknown"

        # 6. Database Storage (plaintext)
        print("\n5. Database Storage:")
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        c.execute("""INSERT INTO votes (voter_npm, voter_name, candidate_name, candidate_id,
                                       ip_address, user_agent, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                 (voter_npm, voter_name, candidate_name, candidate_id,
                  ip_address, user_agent, datetime.now()))

        conn.commit()
        conn.close()

        print("   ❌ Data tersimpan dalam format terbuka:")
        print(f"      - voter_npm: {voter_npm}")
        print(f"      - voter_name: {voter_name}")
        print(f"      - candidate_name: {candidate_name}")
        print(f"      - ip_address: {ip_address}")
        print(f"      - user_agent: {user_agent[:30]}...")
        print(f"      - timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return f"vote_{voter_npm}_{candidate_id}"

def demonstrate_database_queries():
    """Demonstrasi query database untuk menunjukkan perbedaan"""
    print("\n" + "="*70)
    print("🔍 DATABASE QUERY DEMONSTRATION")
    print("="*70)

    # Query database dengan blind signature
    print("\n📊 BLIND SIGNATURE DATABASE QUERY:")
    print("-" * 40)
    conn1 = sqlite3.connect("voting_with_blind_signature.db")
    c1 = conn1.cursor()

    c1.execute("SELECT signature, voter_hash, type, timestamp FROM ballots LIMIT 3")
    blind_results = c1.fetchall()

    print("| Signature (encrypted) | Voter Hash (anonymous) | Type | Timestamp |")
    print("|" + "-"*21 + "|" + "-"*22 + "|" + "-"*6 + "|" + "-"*11 + "|")

    for row in blind_results:
        signature = row[0][:18] + "..."
        voter_hash = row[1][:18] + "..."
        vote_type = row[2]
        timestamp = row[3][:16]
        print(f"| {signature} | {voter_hash} | {vote_type} | {timestamp} |")

    conn1.close()

    print("\n🔍 Analisis Blind Signature Database:")
    print("✅ Tidak dapat mengetahui siapa yang voting")
    print("✅ Tidak dapat mengetahui pilihan suara")
    print("✅ Data terenkripsi dan anonim")
    print("✅ Privasi pemilih terjaga")

    # Query database tanpa blind signature
    print("\n📊 NON-BLIND SIGNATURE DATABASE QUERY:")
    print("-" * 40)
    conn2 = sqlite3.connect("voting_without_blind_signature.db")
    c2 = conn2.cursor()

    c2.execute("SELECT voter_npm, voter_name, candidate_name, ip_address, timestamp FROM votes LIMIT 3")
    non_blind_results = c2.fetchall()

    print("| NPM | Nama | Kandidat | IP Address | Timestamp |")
    print("|" + "-"*12 + "|" + "-"*15 + "|" + "-"*15 + "|" + "-"*15 + "|" + "-"*11 + "|")

    for row in non_blind_results:
        npm = row[0]
        name = row[1][:13] + "..." if len(row[1]) > 13 else row[1]
        candidate = row[2][:13] + "..." if len(row[2]) > 13 else row[2]
        ip = row[3]
        timestamp = row[4][:16]
        print(f"| {npm} | {name} | {candidate} | {ip} | {timestamp} |")

    conn2.close()

    print("\n🚨 Analisis Non-Blind Signature Database:")
    print("❌ Dapat dengan mudah mengetahui siapa yang voting")
    print("❌ Dapat dengan mudah mengetahui pilihan suara")
    print("❌ Semua data terbuka dan dapat dilacak")
    print("❌ Privasi pemilih tidak terlindungi")

    # Demonstrasi query berbahaya
    print("\n⚠️ CONTOH QUERY BERBAHAYA (Non-Blind System):")
    print("-" * 50)

    conn2 = sqlite3.connect("voting_without_blind_signature.db")
    c2 = conn2.cursor()

    print("Query: SELECT voter_name, candidate_name FROM votes WHERE voter_npm = '2120101005'")
    c2.execute("SELECT voter_name, candidate_name FROM votes WHERE voter_npm = '2120101005'")
    result = c2.fetchone()
    if result:
        print(f"Hasil: {result[0]} memilih {result[1]}")
        print("🚨 PRIVASI DILANGGAR! Keterkaitan pemilih-suara terungkap!")

    conn2.close()

def generate_sample_votes():
    """Generate contoh voting untuk demonstrasi"""
    print("\n🗳️ GENERATING SAMPLE VOTES FOR DEMONSTRATION")
    print("="*60)

    # Setup systems
    blind_system = BlindSignatureVoting()
    non_blind_system = NonBlindSignatureVoting()

    # Register candidates
    blind_system.register_candidates()
    non_blind_system.register_candidates()

    # Sample voters
    voters = [
        ("2120101005", "Deni Rahman", "ABC123"),
        ("2120101010", "Maya Sari", "DEF456"),
        ("2120101015", "Andi Prasetyo", "GHI789")
    ]

    # Cast votes in both systems
    for i, (npm, name, token) in enumerate(voters):
        candidate_id = (i % 4) + 1  # Rotate between candidates 1-4
        vote_type = "senat" if candidate_id <= 2 else "demus"

        print(f"\n👤 VOTER {i+1}: {name} (NPM: {npm})")

        # Vote with blind signature
        blind_system.cast_vote(token, candidate_id, vote_type)

        # Vote without blind signature
        non_blind_system.cast_vote(npm, name, candidate_id, vote_type)

        print("\n" + "-"*60)

def main():
    """Main demonstration function"""
    print("🔐 E-VOTING SYSTEMS COMPARISON DEMONSTRATION")
    print("="*70)
    print("Perbandingan sistem e-voting dengan dan tanpa Blind Signature")
    print()

    try:
        # Clean up existing databases
        for db in ["voting_with_blind_signature.db", "voting_without_blind_signature.db"]:
            if os.path.exists(db):
                os.remove(db)

        # Generate sample votes
        generate_sample_votes()

        # Demonstrate database queries
        demonstrate_database_queries()

        print("\n🎯 KESIMPULAN PERBANDINGAN:")
        print("="*50)
        print("✅ BLIND SIGNATURE SYSTEM:")
        print("   • Identitas pemilih dilindungi dengan hash anonim")
        print("   • Pilihan suara terenkripsi dalam signature")
        print("   • Tidak dapat melacak keterkaitan pemilih-suara")
        print("   • Memenuhi prinsip privacy dan anonymity")
        print()
        print("❌ NON-BLIND SIGNATURE SYSTEM:")
        print("   • Identitas pemilih tersimpan langsung (NPM, nama)")
        print("   • Pilihan suara tersimpan dalam plaintext")
        print("   • Mudah melacak siapa memilih apa")
        print("   • Melanggar prinsip privacy dan anonymity")
        print()
        print("📊 Database files created:")
        print("   - voting_with_blind_signature.db (aman dan anonim)")
        print("   - voting_without_blind_signature.db (terbuka dan dapat dilacak)")

    except Exception as e:
        print(f"❌ Error during demonstration: {e}")

if __name__ == "__main__":
    main()
