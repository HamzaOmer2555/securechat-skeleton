import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding # <--- ADDED THIS

CA_CERT_PATH = "certs/ca_cert.pem"

def load_certificate(pem_bytes: bytes) -> x509.Certificate:
    """Parses PEM bytes into an x509 Certificate object."""
    return x509.load_pem_x509_certificate(pem_bytes, backend=default_backend())

def load_private_key(path: str):
    """Loads a private key from disk."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_root_ca():
    """Loads the trusted Root CA certificate from disk."""
    with open(CA_CERT_PATH, "rb") as f:
        return load_certificate(f.read())

def verify_certificate(cert_pem: str, expected_cn: str = None) -> bool:
    """
    Validates a received certificate against the Root CA.
    Checks: Signature, Expiry, and optional Common Name (CN).
    """
    try:
        # 1. Parse the received certificate
        cert = load_certificate(cert_pem.encode('utf-8'))
        
        # 2. Load Root CA
        root_ca = load_root_ca()
        
        # 3. Verify Signature (Chain of Trust)
        # We use the Root CA's public key to verify the signature on the received cert
        root_ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(), # <--- FIXED: Uses the correct imported padding module
            cert.signature_hash_algorithm,
        )

        # 4. Verify Expiry (NotBefore / NotAfter)
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            print(f"[!] Certificate expired or not yet valid.")
            return False

        # 5. Verify Common Name (Identity)
        if expected_cn:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_attr:
                print("[!] Certificate has no Common Name.")
                return False
            cn_val = cn_attr[0].value
            if cn_val != expected_cn:
                print(f"[!] CN Mismatch: Expected '{expected_cn}', got '{cn_val}'")
                return False

        return True

    except Exception as e:
        print(f"[!] Certificate verification failed: {e}")
        return False