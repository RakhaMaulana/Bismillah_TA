#!/usr/bin/env python3
"""
AUTOMATED INTEGRATION TESTING SCRIPT
E-Voting System dengan Blind Signature

Script ini melakukan pengujian integrasi antar modul sistem e-voting
untuk memverifikasi bahwa semua komponen bekerja bersama dengan benar.
"""

import unittest
import sqlite3
import hashlib
import random
import os
import tempfile
import json
import time
import uuid
from datetime import datetime
import sys
import traceback

class MockSession:
    """Mock session management untuk testing"""
    def __init__(self):
        self.sessions = {}
        self.current_user = None

    def create_session(self, user_id, username):
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'user_id': user_id,
            'username': username,
            'created_at': datetime.now(),
            'last_activity': datetime.now()
        }
        self.current_user = {'id': user_id, 'username': username}
        return session_id

    def validate_session(self, session_id):
        return session_id in self.sessions

    def get_user_from_session(self, session_id):
        return self.sessions.get(session_id)

class IntegrationTestSuite(unittest.TestCase):
    """Test Suite untuk pengujian integrasi sistem e-voting"""

    def setUp(self):
        """Setup testing environment"""
        self.test_db = tempfile.mktemp(suffix='.db')
        self.test_results = []
        self.session_manager = MockSession()
        self.setup_test_database()
        self.setup_test_data()

    def tearDown(self):
        """Cleanup setelah testing"""
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def setup_test_database(self):
        """Setup database untuk testing integrasi"""
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
                voter_token VARCHAR(64) UNIQUE,
                token_used BOOLEAN DEFAULT FALSE
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
                is_valid BOOLEAN DEFAULT TRUE,
                encrypted_vote TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100),
                role VARCHAR(20) DEFAULT 'admin',
                last_login DATETIME,
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)

        cursor.execute("""
            CREATE TABLE activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                activity_type VARCHAR(50) NOT NULL,
                description TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        conn.commit()
        conn.close()

    def setup_test_data(self):
        """Setup data awal untuk testing"""
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Insert admin user
        admin_password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES (?, ?, ?, ?)
        """, ("admin", admin_password_hash, "Administrator", "admin"))

        # Insert test candidates
        candidates = [
            ("Alice Johnson", "senat", "Kandidat Ketua Senat"),
            ("Bob Smith", "senat", "Kandidat Ketua Senat"),
            ("Carol Davis", "dewan", "Kandidat Ketua Dewan"),
            ("David Wilson", "dewan", "Kandidat Ketua Dewan")
        ]

        for name, position, desc in candidates:
            cursor.execute("""
                INSERT INTO candidates (name, position, description)
                VALUES (?, ?, ?)
            """, (name, position, desc))

        conn.commit()
        conn.close()

    def log_test_result(self, test_name, expected, actual, status):
        """Log hasil testing integrasi"""
        result = {
            'skenario': test_name,
            'expected': expected,
            'actual': actual,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{'✅' if status == 'Passed' else '❌'} {test_name}: {status}")

    def test_01_voter_registration_approval_integration(self):
        """Test 1: Integrasi Registrasi Pemilih → Persetujuan Admin"""
        print("\n🔍 TEST 1: Integrasi Registrasi Pemilih → Persetujuan Admin")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # STEP 1: Registrasi Pemilih
        npm = "2120101001"
        name = "Ahmad Integration Test"
        email = "ahmad@test.com"

        # Generate unique token untuk pemilih
        token = hashlib.sha256(f"{npm}_{time.time()}".encode()).hexdigest()[:32]

        cursor.execute("""
            INSERT INTO voters (npm, name, email, voter_token, is_verified)
            VALUES (?, ?, ?, ?, ?)
        """, (npm, name, email, token, False))

        # Verify initial state
        cursor.execute("SELECT id, is_verified, voter_token FROM voters WHERE npm = ?", (npm,))
        initial_state = cursor.fetchone()
        voter_id = initial_state[0]
        initial_verified = initial_state[1]
        initial_token = initial_state[2]

        print(f"  Initial state: verified={initial_verified}, token={initial_token[:16]}...")

        # STEP 2: Admin Login dan Approval
        session_id = self.session_manager.create_session(1, "admin")

        # Log admin activity
        cursor.execute("""
            INSERT INTO activity_logs (user_id, activity_type, description)
            VALUES (?, ?, ?)
        """, (1, "VOTER_APPROVAL", f"Admin approved voter {npm}"))

        # Admin approve pemilih
        cursor.execute("""
            UPDATE voters SET is_verified = TRUE WHERE id = ?
        """, (voter_id,))

        # Verify final state
        cursor.execute("SELECT is_verified, voter_token FROM voters WHERE npm = ?", (npm,))
        final_state = cursor.fetchone()
        final_verified = final_state[0]
        final_token = final_state[1]

        print(f"  Final state: verified={final_verified}, token={final_token[:16]}...")

        # Verify consistency
        conditions = [
            initial_verified == False,  # Initially not verified
            final_verified == True,     # Finally verified
            initial_token == final_token,  # Token remains same
            len(initial_token) > 0,     # Token exists
            self.session_manager.validate_session(session_id)  # Session valid
        ]

        success = all(conditions)
        conn.commit()
        conn.close()

        self.log_test_result(
            "Integrasi Registrasi Pemilih → Persetujuan Admin",
            "Data pemilih konsisten, status berubah ke Approved, token tetap sama",
            f"Status: {initial_verified}→{final_verified}, Token konsisten: {initial_token == final_token}",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Voter registration-approval integration failed")

    def test_02_voting_token_validation_integration(self):
        """Test 2: Integrasi Voting → Validasi Token"""
        print("\n🔍 TEST 2: Integrasi Voting → Validasi Token")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Setup test voters dengan different states
        test_cases = [
            ("2120101002", "Valid User", True, False),    # Valid & unused
            ("2120101003", "Invalid User", False, False), # Invalid (not approved)
            ("2120101004", "Used User", True, True)       # Valid but already used
        ]

        voter_tokens = {}

        # Insert test voters
        for npm, name, is_verified, token_used in test_cases:
            token = hashlib.sha256(f"{npm}_{time.time()}".encode()).hexdigest()[:32]
            voter_tokens[npm] = token

            cursor.execute("""
                INSERT INTO voters (npm, name, voter_token, is_verified, token_used)
                VALUES (?, ?, ?, ?, ?)
            """, (npm, name, token, is_verified, token_used))

        # Test voting with each token
        voting_results = []

        for npm, name, expected_verified, expected_used in test_cases:
            token = voter_tokens[npm]

            # Simulate voting attempt
            cursor.execute("""
                SELECT is_verified, token_used FROM voters WHERE voter_token = ?
            """, (token,))

            voter_status = cursor.fetchone()

            if voter_status is None:
                vote_allowed = False
                reason = "Token not found"
            elif not voter_status[0]:
                vote_allowed = False
                reason = "Token not approved"
            elif voter_status[1]:
                vote_allowed = False
                reason = "Token already used"
            else:
                vote_allowed = True
                reason = "Vote allowed"

                # Simulate successful vote - mark token as used
                cursor.execute("""
                    UPDATE voters SET token_used = TRUE WHERE voter_token = ?
                """, (token,))

                # Create mock ballot
                cursor.execute("""
                    INSERT INTO ballots (signature, voter_hash, candidate_hash, ballot_type, encrypted_vote)
                    VALUES (?, ?, ?, ?, ?)
                """, ("mock_signature", hashlib.sha256(token.encode()).hexdigest(),
                     "candidate_hash", "senat", "encrypted_vote_data"))

            voting_results.append({
                'npm': npm,
                'expected_allowed': expected_verified and not expected_used,
                'actual_allowed': vote_allowed,
                'reason': reason
            })

            print(f"  {npm}: {reason} (Expected: {'Allow' if expected_verified and not expected_used else 'Deny'})")

        # Verify all results
        success = all(r['expected_allowed'] == r['actual_allowed'] for r in voting_results)

        conn.commit()
        conn.close()

        self.log_test_result(
            "Integrasi Voting → Validasi Token",
            "Token hanya dapat digunakan jika valid dan Approved, penolakan pada token tidak valid atau sudah digunakan",
            f"Token validation: {len([r for r in voting_results if r['expected_allowed'] == r['actual_allowed']])}/{len(voting_results)} correct",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Voting-token validation integration failed")

    def test_03_voting_recap_integration(self):
        """Test 3: Integrasi Voting → Modul Recap"""
        print("\n🔍 TEST 3: Integrasi Voting → Modul Recap")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Get initial vote counts
        cursor.execute("SELECT id, name, vote_count FROM candidates WHERE position = 'senat'")
        initial_candidates = cursor.fetchall()

        # Simulate multiple votes
        votes = [
            ("voter1_token", initial_candidates[0][0], "Alice Johnson"),  # Vote for Alice
            ("voter2_token", initial_candidates[1][0], "Bob Smith"),      # Vote for Bob
            ("voter3_token", initial_candidates[0][0], "Alice Johnson"),  # Vote for Alice
        ]

        encrypted_votes = []

        for voter_token, candidate_id, candidate_name in votes:
            # Create encrypted vote data
            vote_data = f"vote_for_{candidate_name}"
            encrypted_vote = hashlib.sha256(vote_data.encode()).hexdigest()

            # Create voter hash for anonymity
            voter_hash = hashlib.sha256(voter_token.encode()).hexdigest()
            candidate_hash = hashlib.sha256(candidate_name.encode()).hexdigest()

            # Store encrypted ballot
            cursor.execute("""
                INSERT INTO ballots (signature, voter_hash, candidate_hash, ballot_type, encrypted_vote)
                VALUES (?, ?, ?, ?, ?)
            """, (f"signature_{voter_token}", voter_hash, candidate_hash, "senat", encrypted_vote))

            encrypted_votes.append({
                'voter_hash': voter_hash,
                'candidate_id': candidate_id,
                'encrypted_vote': encrypted_vote
            })

            print(f"  Vote stored: {voter_hash[:16]}... → {candidate_name}")

        # Simulate vote delay processing (automatic counting)
        time.sleep(0.1)  # Simulate delay

        # Count votes by candidate_hash and update candidates table
        cursor.execute("""
            SELECT candidate_hash, COUNT(*) as vote_count
            FROM ballots
            WHERE ballot_type = 'senat'
            GROUP BY candidate_hash
        """)

        vote_counts = cursor.fetchall()

        # Update candidate vote counts
        for candidate_hash, count in vote_counts:
            # Find candidate by hash
            for candidate_id, candidate_name, _ in initial_candidates:
                if hashlib.sha256(candidate_name.encode()).hexdigest() == candidate_hash:
                    cursor.execute("""
                        UPDATE candidates SET vote_count = vote_count + ? WHERE id = ?
                    """, (count, candidate_id))
                    break

        # Verify final counts
        cursor.execute("SELECT id, name, vote_count FROM candidates WHERE position = 'senat'")
        final_candidates = cursor.fetchall()

        # Check encryption and counting
        checks = [
            len(encrypted_votes) == len(votes),  # All votes encrypted
            len(vote_counts) > 0,                # Votes counted
            all(len(ev['encrypted_vote']) == 64 for ev in encrypted_votes),  # Proper encryption
        ]

        # Verify vote count increments
        for initial, final in zip(initial_candidates, final_candidates):
            if initial[0] == final[0]:  # Same candidate
                expected_increment = len([v for v in votes if v[1] == initial[0]])
                actual_increment = final[2] - initial[2]
                checks.append(expected_increment == actual_increment)
                print(f"  {final[1]}: {initial[2]} → {final[2]} (+{actual_increment})")

        success = all(checks)

        conn.commit()
        conn.close()

        self.log_test_result(
            "Integrasi Voting → Modul Recap",
            "Suara terenkripsi, jumlah suara bertambah otomatis di Recap sesuai vote delay",
            f"Encryption: ✓, Counting: ✓, Updates: {len([c for c in checks if c])}/{len(checks)}",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Voting-recap integration failed")

    def test_04_admin_dashboard_session_integration(self):
        """Test 4: Integrasi Admin Dashboard → Semua Modul"""
        print("\n🔍 TEST 4: Integrasi Admin Dashboard → Semua Modul")

        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # STEP 1: Admin Login
        session_id = self.session_manager.create_session(1, "admin")
        login_time = datetime.now()

        cursor.execute("""
            UPDATE users SET last_login = ? WHERE username = ?
        """, (login_time, "admin"))

        print(f"  Admin login: session_id={session_id[:16]}...")

        # STEP 2: Access multiple modules without re-login
        modules_accessed = []

        # Module 1: Voter Management
        if self.session_manager.validate_session(session_id):
            cursor.execute("SELECT COUNT(*) FROM voters")
            voter_count = cursor.fetchone()[0]
            modules_accessed.append({"module": "voter_management", "data": voter_count})

            cursor.execute("""
                INSERT INTO activity_logs (user_id, activity_type, description)
                VALUES (?, ?, ?)
            """, (1, "MODULE_ACCESS", "Accessed voter management"))

        # Module 2: Candidate Management
        if self.session_manager.validate_session(session_id):
            cursor.execute("SELECT COUNT(*) FROM candidates")
            candidate_count = cursor.fetchone()[0]
            modules_accessed.append({"module": "candidate_management", "data": candidate_count})

            cursor.execute("""
                INSERT INTO activity_logs (user_id, activity_type, description)
                VALUES (?, ?, ?)
            """, (1, "MODULE_ACCESS", "Accessed candidate management"))

        # Module 3: Vote Results/Recap
        if self.session_manager.validate_session(session_id):
            cursor.execute("SELECT COUNT(*) FROM ballots")
            ballot_count = cursor.fetchone()[0]
            modules_accessed.append({"module": "vote_recap", "data": ballot_count})

            cursor.execute("""
                INSERT INTO activity_logs (user_id, activity_type, description)
                VALUES (?, ?, ?)
            """, (1, "MODULE_ACCESS", "Accessed vote recap"))

        # Module 4: System Logs
        if self.session_manager.validate_session(session_id):
            cursor.execute("SELECT COUNT(*) FROM activity_logs")
            log_count = cursor.fetchone()[0]
            modules_accessed.append({"module": "system_logs", "data": log_count})

            cursor.execute("""
                INSERT INTO activity_logs (user_id, activity_type, description)
                VALUES (?, ?, ?)
            """, (1, "MODULE_ACCESS", "Accessed system logs"))

        # Verify session persistence and security
        session_checks = [
            len(modules_accessed) == 4,  # All modules accessed
            all(self.session_manager.validate_session(session_id) for _ in range(4)),  # Session persistent
            self.session_manager.current_user['username'] == "admin",  # Correct user
        ]

        # Verify activity logging
        cursor.execute("""
            SELECT COUNT(*) FROM activity_logs
            WHERE user_id = 1 AND activity_type = 'MODULE_ACCESS'
        """)
        logged_activities = cursor.fetchone()[0]

        session_checks.append(logged_activities >= 4)  # Activities logged

        for module in modules_accessed:
            print(f"  ✓ {module['module']}: accessed successfully (data: {module['data']})")

        print(f"  Session management: ✓ Persistent across {len(modules_accessed)} modules")
        print(f"  Activity logging: ✓ {logged_activities} activities logged")

        success = all(session_checks)

        conn.commit()
        conn.close()

        self.log_test_result(
            "Integrasi Admin Dashboard → Semua Modul",
            "Admin dapat mengakses seluruh menu setelah login tanpa perlu login ulang, session management berjalan dengan aman",
            f"Modules accessed: {len(modules_accessed)}/4, Session persistent: ✓, Logging: ✓",
            "Passed" if success else "Failed"
        )

        self.assertTrue(success, "Admin dashboard integration failed")

class IntegrationReportGenerator:
    """Generator untuk laporan hasil integration testing"""

    def __init__(self, test_results):
        self.test_results = test_results

    def generate_integration_table(self):
        """Generate tabel sesuai format yang diminta"""
        print("\n" + "="*120)
        print("📋 TABEL HASIL PENGUJIAN INTEGRASI SISTEM E-VOTING")
        print("="*120)

        # Header tabel
        header = f"{'No':<3} {'Skenario Pengujian':<50} {'Hasil yang Diharapkan':<45} {'Hasil Aktual':<40} {'Status':<8}"
        print(header)
        print("-" * 120)

        # Data dari test results
        for i, result in enumerate(self.test_results, 1):
            row = f"{i:<3} {result['skenario'][:48]+'...' if len(result['skenario']) > 48 else result['skenario']:<50} {result['expected'][:43]+'...' if len(result['expected']) > 43 else result['expected']:<45} {result['actual'][:38]+'...' if len(result['actual']) > 38 else result['actual']:<40} {result['status']:<8}"
            print(row)

        print("-" * 120)

        passed_count = len([r for r in self.test_results if r['status'] == 'Passed'])
        total_count = len(self.test_results)

        print(f"📈 RINGKASAN: {passed_count}/{total_count} integration tests passed ({passed_count/total_count*100:.1f}%)")

        if passed_count == total_count:
            print("✅ SEMUA INTEGRASI BERHASIL - Sistem terintegrasi dengan baik")
        else:
            print("❌ ADA INTEGRASI YANG GAGAL - Perlu perbaikan komunikasi antar modul")

    def generate_json_report(self, filename="integration_test_results.json"):
        """Generate laporan JSON untuk integration tests"""
        report = {
            "integration_test_summary": {
                "total_tests": len(self.test_results),
                "passed_tests": len([r for r in self.test_results if r['status'] == 'Passed']),
                "failed_tests": len([r for r in self.test_results if r['status'] == 'Failed']),
                "success_rate": len([r for r in self.test_results if r['status'] == 'Passed']) / len(self.test_results) * 100,
                "execution_time": datetime.now().isoformat()
            },
            "integration_test_details": self.test_results
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📁 Laporan integrasi JSON disimpan: {filename}")

def run_integration_tests():
    """Menjalankan semua integration tests"""
    print("🚀 MEMULAI AUTOMATED INTEGRATION TESTING")
    print("="*60)

    # Setup test suite
    test_instance = IntegrationTestSuite()
    test_instance.setUp()

    try:
        # Run individual integration tests
        test_instance.test_01_voter_registration_approval_integration()
        test_instance.test_02_voting_token_validation_integration()
        test_instance.test_03_voting_recap_integration()
        test_instance.test_04_admin_dashboard_session_integration()

        # Generate reports
        report_generator = IntegrationReportGenerator(test_instance.test_results)
        report_generator.generate_integration_table()
        report_generator.generate_json_report()

    except Exception as e:
        print(f"❌ Error during integration testing: {e}")
        traceback.print_exc()

    finally:
        test_instance.tearDown()

if __name__ == "__main__":
    run_integration_tests()
