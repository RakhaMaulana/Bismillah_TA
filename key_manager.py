"""
Global Key Manager untuk E-Voting System
Memastikan konsistensi key pair RSA di seluruh sistem
"""
import sqlite3
import BlindSig as bs
from createdb import get_db_connection

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
        """Initialize atau load existing keys dari database"""
        conn = get_db_connection()
        c = conn.cursor()
        
        # Cek apakah ada key di database
        c.execute("SELECT n, e FROM keys ORDER BY timestamp DESC LIMIT 1")
        existing_key = c.fetchone()
        
        if existing_key:
            # Ada key di database, tapi kita tidak bisa restore private key
            # Solusi sementara: generate signer baru tapi catat untuk migrasi
            print(f"WARNING: Found existing keys in DB but cannot restore private key")
            print(f"Existing key: n={existing_key[0]}, e={existing_key[1]}")
            print(f"Will generate new keys and update database")
            
            # Generate signer baru
            self._signer = bs.Signer()
            new_n = self._signer.public_key['n']
            new_e = self._signer.public_key['e']
            
            # Update database dengan key baru
            c.execute("UPDATE keys SET n = ?, e = ?, timestamp = CURRENT_TIMESTAMP WHERE timestamp = (SELECT MAX(timestamp) FROM keys)",
                     (str(new_n), str(new_e)))
            print(f"Updated keys in DB: n={new_n}, e={new_e}")
        else:
            # Tidak ada key, buat baru
            print("No existing keys found, creating new ones")
            self._signer = bs.Signer()
            n = self._signer.public_key['n']
            e = self._signer.public_key['e']
            
            # Simpan ke database
            c.execute("INSERT INTO keys (n, e, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)",
                     (str(n), str(e)))
            print(f"Saved new keys to DB: n={n}, e={e}")
        
        conn.commit()
        conn.close()
    
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
