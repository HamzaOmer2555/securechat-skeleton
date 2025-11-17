import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Configuration
CA_KEY_PATH = "certs/ca_key.pem"
CA_CERT_PATH = "certs/ca_cert.pem"

def generate_ca():
    print(f"[*] Generating Root CA...")

    # 1. Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Create Self-Signed Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"FAST-NU Root CA"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # 3. Save Private Key
    os.makedirs("certs", exist_ok=True)
    with open(CA_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # 4. Save Certificate
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA generated successfully.")
    print(f"    Key:  {CA_KEY_PATH}")
    print(f"    Cert: {CA_CERT_PATH}")

if __name__ == "__main__":
    generate_ca()