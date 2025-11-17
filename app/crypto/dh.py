import hashlib
import secrets

# Standard RFC 3526 2048-bit MODP Group (Safe Prime for DH)
# It is cleaner to hardcode a known safe prime than generate one every time (which is slow).
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DEFAULT_G = 2

class DiffieHellman:
    def __init__(self, p=DEFAULT_P, g=DEFAULT_G):
        self.p = p
        self.g = g
        # Generate private key 'a' (random integer in [2, p-2])
        self.private_key = secrets.randbelow(self.p - 2) + 2
        
    def get_public_key(self) -> int:
        """Computes A = g^a mod p"""
        return pow(self.g, self.private_key, self.p)
    
    def compute_shared_secret(self, peer_public_key: int) -> int:
        """Computes Ks = B^a mod p"""
        return pow(peer_public_key, self.private_key, self.p)
    
    @staticmethod
    def derive_session_key(shared_secret_int: int) -> bytes:
        """
        Derives AES key: K = Trunc16(SHA256(big-endian(Ks)))
        """
        # Convert int to bytes (big-endian)
        # We use ceil(bit_length / 8) to determine byte size
        byte_len = (shared_secret_int.bit_length() + 7) // 8
        shared_bytes = shared_secret_int.to_bytes(byte_len, byteorder='big')
        
        # SHA-256 hash
        digest = hashlib.sha256(shared_bytes).digest()
        
        # Truncate to 16 bytes
        return digest[:16]