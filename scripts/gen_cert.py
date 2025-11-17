import argparse
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Paths to CA
CA_KEY_PATH = "certs/ca_key.pem"
CA_CERT_PATH = "certs/ca_cert.pem"

def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
    return key, cert

def generate_cert(cn, output_base):
    print(f"[*] Issuing certificate for CN={cn}...")
    
    ca_key, ca_cert = load_ca()

    # 1. Generate Entity Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Build Certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject # Signed by CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # 3. Save Files
    key_path = f"{output_base}_key.pem"
    cert_path = f"{output_base}_crt.pem"

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate issued: {cert_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name (e.g. server.local)")
    parser.add_argument("--out", required=True, help="Output filename base (e.g. certs/server)")
    args = parser.parse_args()
    
    generate_cert(args.cn, args.out)