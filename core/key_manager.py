"""
Global Key Manager untuk E-Voting System
Memastikan konsistensi key pair RSA di seluruh sistem
"""
import sqlite3
import core.BlindSig as bs
from core.createdb import get_db_connection

class GlobalKeyManager:
    _instance = None
    _signer = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalKeyManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._signer is None:
            self._initialize_keys()

    def _initialize_keys(self):
        """Initialize atau load existing keys dari database dengan proper key management"""
        conn = get_db_connection()
        c = conn.cursor()

        # Cek apakah ada key aktif di database
        c.execute("SELECT id, n, e FROM keys WHERE is_active = 1 ORDER BY id DESC LIMIT 1")
        existing_key = c.fetchone()

        if existing_key:
            # Ada key aktif di database, tapi kita tidak bisa restore private key
            key_id, n_str, e_str = existing_key
            print(f"WARNING: Found active key (id={key_id}) in DB but cannot restore private key")
            print(f"Existing key: n={n_str}, e={e_str}")
            print(f"Will generate new keys and update database")

            # Generate signer baru untuk konsistensi
            self._signer = bs.Signer()
            new_n = self._signer.public_key['n']
            new_e = self._signer.public_key['e']
            new_d = self._signer.private_key['d']

            # Deaktifkan key lama dan buat key baru
            c.execute("UPDATE keys SET is_active = 0 WHERE is_active = 1")
            c.execute("INSERT INTO keys (n, e, is_active, timestamp) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
                     (str(new_n), str(new_e)))
            new_key_id = c.lastrowid

            # Simpan private key sementara
            import uuid
            session_id = str(uuid.uuid4())
            c.execute("INSERT INTO temp_private_keys (d, session_id, key_id) VALUES (?, ?, ?)",
                     (str(new_d), session_id, new_key_id))

            print(f"Updated keys in DB: id={new_key_id}, n={new_n}, e={new_e}")
        else:
            # Tidak ada key aktif, buat baru
            print("No active keys found, creating new ones")
            self._signer = bs.Signer()
            n = self._signer.public_key['n']
            e = self._signer.public_key['e']
            d = self._signer.private_key['d']

            # Simpan ke database sebagai key aktif
            c.execute("INSERT INTO keys (n, e, is_active, timestamp) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
                     (str(n), str(e)))
            new_key_id = c.lastrowid

            # Simpan private key sementara
            import uuid
            session_id = str(uuid.uuid4())
            c.execute("INSERT INTO temp_private_keys (d, session_id, key_id) VALUES (?, ?, ?)",
                     (str(d), session_id, new_key_id))

            print(f"Saved new keys to DB: id={new_key_id}, n={n}, e={e}")

        conn.commit()
        conn.close()

    def get_active_key_id(self):
        """Return ID dari key yang sedang aktif"""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM keys WHERE is_active = 1 ORDER BY id DESC LIMIT 1")
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    def get_signer(self):
        """Return signer instance yang konsisten"""
        return self._signer

    def get_public_key(self):
        """Return public key dictionary"""
        return self._signer.get_public_key()

    def get_private_key(self):
        """Return private key dictionary"""
        return self._signer.private_key

    def get_key_info(self):
        """Return semua informasi key untuk debugging"""
        public_key = self.get_public_key()
        private_key = self.get_private_key()
        return {
            'n': public_key['n'],
            'e': public_key['e'],
            'd': private_key['d']
        }

    def sign_message(self, message):
        """Sign message menggunakan signer yang konsisten"""
        return self._signer.sign(message)

    def verify_signature(self, message, signature):
        """Verify signature menggunakan key yang konsisten"""
        public_key = self.get_public_key()
        return bs.verify_signature(message, signature, public_key['e'], public_key['n'])

# Global instance
key_manager = GlobalKeyManager()

def get_global_signer():
    """Get global signer instance"""
    return key_manager.get_signer()

def get_global_keys():
    """Get global key info sebagai dict"""
    return key_manager.get_key_info()

def sign_with_global_key(message):
    """Sign message dengan global key"""
    return key_manager.sign_message(message)

def verify_with_global_key(message, signature):
    """Verify signature dengan global key"""
    return key_manager.verify_signature(message, signature)
