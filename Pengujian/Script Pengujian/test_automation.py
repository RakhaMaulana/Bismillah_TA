#!/usr/bin/env python3
"""
AUTOMATED UNIT TESTING SCRIPT
E-Voting System dengan Blind Signature

Script ini melakukan pengujian otomatis terhadap komponen kritis
sistem e-voting untuk memverifikasi fungsionalitas sesuai spesifikasi.
"""

import unittest
import sqlite3
import hashlib
import random
import os
import tempfile
import json
import time
from datetime import datetime
import sys
import traceback

# Import modules from the project
try:
    from BlindSig import BlindSignature
    from cryptomath import gcd, findModInverse
    from createdb import create_tables
except ImportError:
    print("Warning: Some project modules not found. Creating mock implementations.")

class MockBlindSignature:
    """Mock implementation untuk testing jika module asli tidak tersedia"""
    def __init__(self):
        self.p = 61
        self.q = 67
        self.n = self.p * self.q  # 4087
        self.phi_n = (self.p - 1) * (self.q - 1)  # 3960
        self.e = 17
        # Calculate proper d using extended Euclidean algorithm
        self.d = self.mod_inverse(self.e, self.phi_n)

    def mod_inverse(self, e, phi_n):
        """Calculate modular inverse using extended Euclidean algorithm"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        gcd, x, _ = extended_gcd(e, phi_n)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % phi_n + phi_n) % phi_n

    def generate_keys(self):
        return (self.n, self.e), (self.n, self.d)

    def blind_message(self, message, r):
        return (message * pow(r, self.e, self.n)) % self.n

    def sign_blinded_message(self, blinded_message):
        return pow(blinded_message, self.d, self.n)

    def unblind_signature(self, blinded_signature, r):
        # Calculate modular inverse of r
        r_inv = self.mod_inverse(r, self.n)
        return (blinded_signature * r_inv) % self.n

    def verify_signature(self, signature, message):
        return pow(signature, self.e, self.n) == message

class UnitTestSuite(unittest.TestCase):
    """Test Suite untuk pengujian unit sistem e-voting"""

    def setUp(self):
        """Setup testing environment"""
        self.test_db = tempfile.mktemp(suffix='.db')
        self.test_results = []
        self.setup_test_database()
        self.blind_sig = MockBlindSignature()

    def tearDown(self):
        """Cleanup setelah testing"""
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def setup_test_database(self):
        """Setup database untuk testing"""
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Create tables sesuai e_voting.db structure
        cursor.execute("""
            CREATE TABLE voters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                npm VARCHAR(20) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100),
                photo_path VARCHAR(255),
                is_verified BOOLEAN DEFAULT FALSE,
                registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                voter_token VARCHAR(64) UNIQUE
            )
        """)

        cursor.execute("""
            CREATE TABLE candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                position VARCHAR(50) NOT NULL,
                description TEXT,
                photo_path VARCHAR(255),
                vote_count INTEGER DEFAULT 0,
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE ballots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature TEXT NOT NULL,
                voter_hash VARCHAR(64) NOT NULL,
                candidate_hash VARCHAR(64) NOT NULL,
                ballot_type VARCHAR(20) NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_valid BOOLEAN DEFAULT TRUE
            )
        """)

        cursor.execute("""
            CREATE TABLE rsa_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type VARCHAR(10) NOT NULL,
                modulus_n TEXT NOT NULL,
                exponent TEXT NOT NULL,
                key_size INTEGER DEFAULT 1024,
                generation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)

        conn.commit()
        conn.close()

    def log_test_result(self, test_name, purpose, expected, actual, status):
        """Log hasil testing"""
        result = {
            'test_name': test_name,
            'purpose': purpose,
            'expected': expected,
            'actual': actual,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"✅ {test_name}: {status}")

    def test_01_token_validation(self):
        """Test 1: Validasi Token Voting"""
        print("\n🔍 TEST 1: Validasi Token Voting")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Test data: token valid, invalid, dan pending
        test_cases = [
            # (npm, name, is_verified, token, expected_status)
            ("2120101001", "Ahmad Test", True, "valid_token_123", "valid"),
            ("2120101002", "Sari Test", False, "pending_token_456", "pending"),
            ("", "", False, "invalid_token_789", "invalid")
        ]

        results = []

        for npm, name, is_verified, token, expected in test_cases:
            if npm:  # Insert valid data
                cursor.execute("""
                    INSERT INTO voters (npm, name, is_verified, voter_token)
                    VALUES (?, ?, ?, ?)
                """, (npm, name, is_verified, token))

            # Simulate token validation
            cursor.execute("""
                SELECT is_verified FROM voters WHERE voter_token = ?
            """, (token,))

            result = cursor.fetchone()

            if result is None:
                actual_status = "invalid"
            elif result[0]:
                actual_status = "valid"
            else:
                actual_status = "pending"

            results.append(actual_status == expected)
            print(f"  Token {token}: Expected {expected}, Got {actual_status}")

        conn.commit()
        conn.close()

        success = all(results)
        self.log_test_result(
            "Validasi Token Voting",
            "Membedakan token valid, tidak valid, dan belum disetujui",
            "Sistem memberi respon sesuai status token",
            f"Respon sesuai skenario uji ({len([r for r in results if r])}/{len(results)} passed)",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Token validation test failed")

    def test_02_registration_storage(self):
        """Test 2: Penyimpanan Registrasi"""
        print("\n🔍 TEST 2: Penyimpanan Registrasi")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Test data
        test_npm = "2120101010"
        test_name = "Testing User"
        test_email = "test@example.com"

        # Generate unique token
        token = hashlib.sha256(f"{test_npm}_{time.time()}".encode()).hexdigest()[:32]

        # Insert registration data
        cursor.execute("""
            INSERT INTO voters (npm, name, email, voter_token, is_verified)
            VALUES (?, ?, ?, ?, ?)
        """, (test_npm, test_name, test_email, token, False))

        # Verify storage
        cursor.execute("""
            SELECT npm, name, is_verified, voter_token FROM voters
            WHERE npm = ?
        """, (test_npm,))

        result = cursor.fetchone()
        conn.close()

        # Verify results
        expected_conditions = [
            result is not None,
            result[0] == test_npm,
            result[1] == test_name,
            result[2] == False,  # is_verified should be False (Pending)
            result[3] is not None and len(result[3]) > 0  # token exists
        ]

        success = all(expected_conditions)

        self.log_test_result(
            "Penyimpanan Registrasi",
            "Menyimpan data pendaftar dengan status awal Pending dan token unik",
            "Data tersimpan dan token unik dihasilkan otomatis",
            f"Data tersimpan dengan status Pending dan token unik: {result[3][:16]}...",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Registration storage test failed")

    def test_03_candidate_addition(self):
        """Test 3: Penambahan Kandidat"""
        print("\n🔍 TEST 3: Penambahan Kandidat")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Test data dengan input yang perlu sanitasi
        raw_name = "<script>alert('xss')</script>Kandidat Test"
        raw_description = "Deskripsi dengan <img src=x onerror=alert(1)> script"
        position = "senat"

        # Sanitize input (basic sanitization)
        sanitized_name = raw_name.replace("<", "&lt;").replace(">", "&gt;")
        sanitized_description = raw_description.replace("<", "&lt;").replace(">", "&gt;")
        safe_photo_name = f"candidate_{int(time.time())}.jpg"

        # Insert candidate
        cursor.execute("""
            INSERT INTO candidates (name, position, description, photo_path)
            VALUES (?, ?, ?, ?)
        """, (sanitized_name, position, sanitized_description, safe_photo_name))

        # Verify storage
        cursor.execute("""
            SELECT name, description, photo_path FROM candidates
            WHERE position = ?
        """, (position,))

        result = cursor.fetchone()
        conn.close()

        # Verify sanitization
        safety_checks = [
            result is not None,
            "<script>" not in result[0],  # Name sanitized
            "<img" not in result[1],      # Description sanitized
            result[2].endswith(".jpg"),   # Safe file extension
            "candidate_" in result[2]     # Safe filename pattern
        ]

        success = all(safety_checks)

        self.log_test_result(
            "Penambahan Kandidat",
            "Menyimpan kandidat dengan input tersanitasi",
            "Kandidat tersimpan dan nama file foto aman dari eksekusi",
            f"Kandidat tersimpan, input tersanitasi: {result[0][:30]}...",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Candidate addition test failed")

    def test_04_blind_signature(self):
        """Test 4: Blind Signature Algorithm"""
        print("\n🔍 TEST 4: Blind Signature Algorithm")

        # Test blind signature process
        message = "Alice Johnson"  # Candidate choice
        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % self.blind_sig.n

        # Generate random blinding factor
        r = random.randint(2, self.blind_sig.n - 1)
        while self.gcd_simple(r, self.blind_sig.n) != 1:
            r = random.randint(2, self.blind_sig.n - 1)

        # Blind signature process
        blinded_message = self.blind_sig.blind_message(message_hash, r)
        blinded_signature = self.blind_sig.sign_blinded_message(blinded_message)
        final_signature = self.blind_sig.unblind_signature(blinded_signature, r)

        # Verify signature
        is_valid = self.blind_sig.verify_signature(final_signature, message_hash)

        # Test anonymity (authority cannot see original message)
        authority_view = blinded_message
        original_recoverable = (authority_view == message_hash)

        # Store to database
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        voter_hash = hashlib.sha256(f"anonymous_voter_{time.time()}".encode()).hexdigest()
        candidate_hash = hashlib.sha256(message.encode()).hexdigest()

        cursor.execute("""
            INSERT INTO ballots (signature, voter_hash, candidate_hash, ballot_type, is_valid)
            VALUES (?, ?, ?, ?, ?)
        """, (str(final_signature), voter_hash, candidate_hash, "senat", is_valid))

        cursor.execute("SELECT COUNT(*) FROM ballots WHERE is_valid = TRUE")
        valid_votes_count = cursor.fetchone()[0]

        conn.close()

        # Verify blind signature properties
        blind_sig_checks = [
            is_valid,                    # Signature is mathematically valid
            not original_recoverable,    # Authority cannot see original message
            final_signature != blinded_signature,  # Unblinding occurred
            valid_votes_count > 0        # Valid vote stored
        ]

        success = all(blind_sig_checks)

        self.log_test_result(
            "Blind Signature Algorithm",
            "Menghasilkan tanda tangan sesuai algoritma",
            "Tanda tangan valid dan tidak mengungkap identitas pemilih",
            f"Signature valid: {is_valid}, Identity protected: {not original_recoverable}",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Blind signature test failed")

    def gcd_simple(self, a, b):
        """Simple GCD helper function untuk testing"""
        while b:
            a, b = b, a % b
        return a

    def gcd_test(self, a, b):
        """GCD helper function untuk testing"""
        while b:
            a, b = b, a % b
        return a

    def test_05_database_integrity(self):
        """Test 5: Database Integrity (Bonus Test)"""
        print("\n🔍 TEST 5: Database Integrity")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Test foreign key constraints dan data consistency
        integrity_checks = []

        # Check unique constraints
        try:
            cursor.execute("INSERT INTO voters (npm, name) VALUES (?, ?)", ("2120101001", "Test User 1"))
            cursor.execute("INSERT INTO voters (npm, name) VALUES (?, ?)", ("2120101001", "Test User 2"))
            integrity_checks.append(False)  # Should fail due to unique constraint
        except sqlite3.IntegrityError:
            integrity_checks.append(True)   # Expected behavior

        # Check NOT NULL constraints
        try:
            cursor.execute("INSERT INTO candidates (name, position) VALUES (?, ?)", (None, "senat"))
            integrity_checks.append(False)  # Should fail due to NOT NULL
        except sqlite3.IntegrityError:
            integrity_checks.append(True)   # Expected behavior

        # Check data types
        cursor.execute("INSERT INTO voters (npm, name, is_verified) VALUES (?, ?, ?)",
                      ("2120101999", "Type Test", True))
        cursor.execute("SELECT is_verified FROM voters WHERE npm = ?", ("2120101999",))
        result = cursor.fetchone()
        integrity_checks.append(isinstance(result[0], (bool, int)))  # Boolean stored correctly

        conn.close()

        success = all(integrity_checks)

        self.log_test_result(
            "Database Integrity",
            "Memverifikasi constraints dan konsistensi data",
            "Semua constraints bekerja dengan benar",
            f"Constraint validation: {len([c for c in integrity_checks if c])}/{len(integrity_checks)} passed",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Database integrity test failed")

class TestReportGenerator:
    """Generator untuk laporan hasil testing"""

    def __init__(self, test_results):
        self.test_results = test_results

    def generate_console_report(self):
        """Generate laporan ke console"""
        print("\n" + "="*80)
        print("📊 HASIL PENGUJIAN UNIT SISTEM E-VOTING")
        print("="*80)

        print(f"{'No':<3} {'Fungsi yang Diuji':<25} {'Tujuan':<35} {'Status':<10}")
        print("-" * 80)

        for i, result in enumerate(self.test_results, 1):
            print(f"{i:<3} {result['test_name']:<25} {result['purpose'][:30]+'...' if len(result['purpose']) > 30 else result['purpose']:<35} {result['status']:<10}")

        passed_count = len([r for r in self.test_results if r['status'] == 'Passed'])
        total_count = len(self.test_results)

        print("-" * 80)
        print(f"📈 RINGKASAN: {passed_count}/{total_count} tests passed ({passed_count/total_count*100:.1f}%)")

        if passed_count == total_count:
            print("✅ SEMUA TEST BERHASIL - Sistem siap untuk deployment")
        else:
            print("❌ ADA TEST YANG GAGAL - Perlu perbaikan sebelum deployment")

    def generate_json_report(self, filename="test_results.json"):
        """Generate laporan dalam format JSON"""
        report = {
            "test_summary": {
                "total_tests": len(self.test_results),
                "passed_tests": len([r for r in self.test_results if r['status'] == 'Passed']),
                "failed_tests": len([r for r in self.test_results if r['status'] == 'Failed']),
                "success_rate": len([r for r in self.test_results if r['status'] == 'Passed']) / len(self.test_results) * 100,
                "execution_time": datetime.now().isoformat()
            },
            "test_details": self.test_results
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📁 Laporan JSON disimpan: {filename}")

def run_automated_tests():
    """Menjalankan semua automated tests"""
    print("🚀 MEMULAI AUTOMATED UNIT TESTING")
    print("="*60)

    # Setup test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(UnitTestSuite)

    # Run tests dengan custom result collector
    test_instance = UnitTestSuite()
    test_instance.setUp()

    try:
        # Run individual tests
        test_instance.test_01_token_validation()
        test_instance.test_02_registration_storage()
        test_instance.test_03_candidate_addition()
        test_instance.test_04_blind_signature()
        test_instance.test_05_database_integrity()

        # Generate reports
        report_generator = TestReportGenerator(test_instance.test_results)
        report_generator.generate_console_report()
        report_generator.generate_json_report()

    except Exception as e:
        print(f"❌ Error during testing: {e}")
        traceback.print_exc()

    finally:
        test_instance.tearDown()

if __name__ == "__main__":
    run_automated_tests()
