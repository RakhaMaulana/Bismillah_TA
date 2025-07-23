import cryptomath
import random
import hashlib
import math

# n has to be greater than m otherwise lossy message
class Signer:

    def __init__(self):
        self.public_key, self.private_key = self.generate_information()

    @staticmethod
    def generate_information():
        # Generates public and private keys
        p = cryptomath.find_prime()
        q = cryptomath.find_prime()
        phi = (p - 1) * (q - 1)
        n = p * q

        found_encryption_key = False
        while not found_encryption_key:
            e = random.randint(2, phi - 1)
            if cryptomath.gcd(e, phi) == 1:
                found_encryption_key = True
        v = False
        if cryptomath.gcd(e, phi) == 1:
            v = True
        d = cryptomath.find_mod_inverse(e, phi)
        v = False
        if (e * d % phi) == 1:
            v = True
        public_info = {"n": n, "e": e}
        private_info = {"n": n, "d": d}

        return [public_info, private_info]

    def get_public_key(self):
        return self.public_key

    def sign_message(self, message, eligible):
        if eligible == "y":
            # PERBAIKAN: Validasi input message
            if message is None or message <= 0:
                return None

            # PERBAIKAN: Pastikan message tidak lebih besar dari n
            if message >= self.public_key['n']:
                message = message % self.public_key['n']

            try:
                s = pow(message, self.private_key['d'], self.public_key['n'])
                return s
            except (ValueError, OverflowError):
                return None
        return None

    def verify_voter(self, eligible):
        # This method is intentionally left empty
        pass


class Voter:

    def __init__(self, n, eligible, additional_entropy=None):
        self.eligible = eligible

        # PERBAIKAN: Validasi input n
        if n <= 1:
            raise ValueError("Modulus n must be greater than 1")

        # PERBAIKAN: Tambahkan entropy tambahan untuk memastikan uniqueness
        if additional_entropy is None:
            import time
            import os
            additional_entropy = str(time.time_ns()) + str(os.urandom(16).hex())

        # Seed random dengan entropy tambahan
        entropy_hash = int(hashlib.sha256(additional_entropy.encode()).hexdigest(), 16)
        random.seed(entropy_hash)

        found_r = False
        max_attempts = 1000  # Prevent infinite loop
        attempts = 0

        while not found_r and attempts < max_attempts:
            # PERBAIKAN: Memastikan r relatif prima dengan n dengan entropy tambahan
            base_r = random.randint(2, n - 1)
            # Tambahkan entropy untuk memastikan uniqueness
            entropy_mod = (entropy_hash % (n - 3)) + 2
            self.r = (base_r + entropy_mod) % n
            if self.r >= 2 and math.gcd(self.r, n) == 1:
                found_r = True
            attempts += 1

        if not found_r:
            raise ValueError("Unable to find suitable blinding factor r")

        # Verifikasi bahwa r benar-benar relatif prima dengan n
        if math.gcd(self.r, n) != 1:
            raise ValueError("Blinding factor r is not coprime with n")

    def unwrap_signature(self, signed_blind_message, n):
        # PERBAIKAN: Validasi input
        if signed_blind_message is None or signed_blind_message <= 0:
            return None

        try:
            # PERBAIKAN: Menggunakan fungsi dari cryptomath jika tersedia, atau implementasi sendiri
            r_inv = cryptomath.find_mod_inverse(self.r, n)

            if r_inv is None:
                return None

            # Verifikasi bahwa r_inv benar
            if (self.r * r_inv) % n != 1:
                return None

            s = (signed_blind_message * r_inv) % n
            print(f"DEBUG unwrap_signature:")
            print(f"  - signed_blind_message: {signed_blind_message}")
            print(f"  - r: {self.r}")
            print(f"  - r_inv: {r_inv}")
            print(f"  - s (unwrapped): {s}")
            return s

        except (ValueError, TypeError, ZeroDivisionError):
            return None

    def blind_message(self, m, n, e):
        # PERBAIKAN: Pastikan message tidak lebih besar dari n
        if m >= n:
            m = m % n

        # Blind message: m' = m * r^e mod n
        r_e = pow(self.r, e, n)
        blind_message = (m * r_e) % n
        print(f"DEBUG blind_message:")
        print(f"  - original message: {m}")
        print(f"  - r: {self.r}")
        print(f"  - r^e mod n: {r_e}")
        print(f"  - blinded message: {blind_message}")
        return blind_message

    def get_eligibility(self):
        return self.eligible


def verify_signature(candidate_id, signature, public_e, public_n):
    """
    Verifikasi tanda tangan sesuai protokol blind signature standar
    σ^e mod n = H(m)

    Args:
        candidate_id: ID kandidat (pesan yang ditandatangani)
        signature: Tanda tangan yang akan diverifikasi
        public_e: Eksponen publik e
        public_n: Modulus n

    Returns:
        bool: True jika verifikasi berhasil, False jika gagal
    """
    try:
        # PERBAIKAN: Implementasi verifikasi yang akurat
        # Dekripsi tanda tangan menggunakan kunci publik
        decrypted = pow(int(signature), public_e, public_n)

        # Hitung hash dari candidate_id dengan cara yang sama seperti saat signing
        message_hash = hashlib.sha256(str(candidate_id).encode()).hexdigest()
        message_hash_int = int(message_hash, 16)

        # PERBAIKAN: Pastikan hash tidak lebih besar dari modulus
        if message_hash_int >= public_n:
            message_hash_int = message_hash_int % public_n

        print(f"DEBUG verify_signature:")
        print(f"  - candidate_id: {candidate_id}")
        print(f"  - message_hash: {message_hash}")
        print(f"  - message_hash_int: {message_hash_int}")
        print(f"  - signature: {signature}")
        print(f"  - decrypted: {decrypted}")
        print(f"  - equal: {decrypted == message_hash_int}")

        # Bandingkan hasil dekripsi dengan hash
        return decrypted == message_hash_int

    except (ValueError, TypeError, OverflowError) as e:
        # Handle invalid signature or mathematical errors
        print(f"DEBUG: Error in verify_signature: {e}")
        return False