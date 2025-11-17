import socket
import json
import sys
from app.common.utils import read_file, generate_nonce
from app.common.protocol import HelloMsg, ServerHelloMsg
from app.crypto.pki import verify_certificate

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8080
CERT_FILE = 'certs/client_crt.pem'
KEY_FILE = 'certs/client_key.pem'

class SecureChatClient:
    def __init__(self):
        self.sock = None
        self.cert_pem = read_file(CERT_FILE)
        self.key_pem = read_file(KEY_FILE)

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")
            
            self.handshake()
            
            # Keep alive for testing
            input("[*] Handshake complete. Press Enter to exit...")
            self.sock.close()

        except Exception as e:
            print(f"[-] Connection failed: {e}")

    def handshake(self):
        # 1. Send Hello [cite: 67]
        msg = HelloMsg(
            client_cert=self.cert_pem,
            nonce=generate_nonce()
        )
        self.sock.sendall(json.dumps(msg.model_dump()).encode('utf-8'))
        print("[*] Sent Hello. Waiting for Server...")

        # 2. Receive Server Hello
        data = self.sock.recv(4096)
        resp_dict = json.loads(data.decode('utf-8'))
        server_hello = ServerHelloMsg(**resp_dict)

        # 3. Verify Server Certificate [cite: 162]
        print("[*] Verifying Server Certificate...")
        if not verify_certificate(server_hello.server_cert, expected_cn="server.local"):
            print("[-] Server Certificate Verification FAILED. Aborting.")
            self.sock.close()
            sys.exit(1)
            
        print("[+] Server Authenticated. Secure Channel Negotiated (Pre-Auth).")

if __name__ == "__main__":
    client = SecureChatClient()
    client.connect()