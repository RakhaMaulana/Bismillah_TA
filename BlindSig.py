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
            s = pow(message, self.private_key['d'], self.public_key['n'])
            return s
        return None

    def verify_voter(self, eligible):
        # This method is intentionally left empty
        pass


class Voter:

    def __init__(self, n, eligible):
        self.eligible = eligible

        found_r = False
        while not found_r:
            # PERBAIKAN: Memastikan r relatif prima dengan n
            self.r = random.randint(2, n - 1)
            if math.gcd(self.r, n) == 1:
                found_r = True
        v = False
        if math.gcd(self.r, n) == 1:
            v = True

    def unwrap_signature(self, signed_blind_message, n):
        # PERBAIKAN: Menggunakan fungsi dari cryptomath jika tersedia, atau implementasi sendiri
        r_inv = cryptomath.find_mod_inverse(self.r, n)
        v = False
        if self.r * r_inv % n == 1:
            v = True
        s = (signed_blind_message * r_inv) % n
        return s

    def blind_message(self, m, n, e):
        blind_message = (m * pow(self.r, e, n)) % n
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
    # PERBAIKAN: Implementasi verifikasi yang akurat
    # Dekripsi tanda tangan menggunakan kunci publik
    decrypted = pow(int(signature), public_e, public_n)

    # Hitung hash dari candidate_id
    message_hash = int(hashlib.sha256(str(candidate_id).encode()).hexdigest(), 16)

    # Bandingkan hasil dekripsi dengan hash
    return decrypted == message_hash