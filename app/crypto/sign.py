from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Constants
RSA_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

def generate_keypair():
    """Generates a new RSA 2048-bit private key."""
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )

def serialize_public_key(public_key) -> str:
    """Converts public key object to PEM format string."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def load_public_key(pem_str: str):
    """Loads a public key from a PEM string."""
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )

def sign_data(private_key, data: bytes) -> bytes:
    """
    Computes SHA-256 hash of data and signs it using RSA-PKCS#1v1.5.
    Returns raw signature bytes.
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data: bytes, signature: bytes):
    """
    Verifies the RSA-SHA256 signature. 
    Raises cryptography.exceptions.InvalidSignature if invalid.
    """
    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )