import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self, key: bytes):
        """
        Initialize with a 16-byte AES key.
        """
        if len(key) != 16:
            raise ValueError("AES key must be exactly 16 bytes (128-bit).")
        self.key = key

    def encrypt(self, plaintext: bytes) -> str:
        """
        Applies PKCS#7 padding, encrypts using AES-128 (ECB), 
        and returns Base64 string.
        """
        # 1. Pad the plaintext (PKCS#7)
        padder = padding.PKCS7(128).padder() # 128-bit block size for AES
        padded_data = padder.update(plaintext) + padder.finalize()

        # 2. Encrypt (AES-128 ECB)
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ct_bytes = encryptor.update(padded_data) + encryptor.finalize()

        # 3. Return Base64 string
        return base64.b64encode(ct_bytes).decode('utf-8')

    def decrypt(self, b64_ciphertext: str) -> bytes:
        """
        Decodes Base64, decrypts AES-128 (ECB), removes PKCS#7 padding, 
        and returns raw bytes.
        """
        # 1. Decode Base64
        ct_bytes = base64.b64decode(b64_ciphertext)

        # 2. Decrypt
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ct_bytes) + decryptor.finalize()

        # 3. Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext