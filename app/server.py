import socket
import json
import threading
import sys
from app.common.utils import read_file, generate_nonce
from app.common.protocol import HelloMsg, ServerHelloMsg
from app.crypto.pki import verify_certificate

# Configuration
HOST = '0.0.0.0'
PORT = 8080
CERT_FILE = 'certs/server_crt.pem'
KEY_FILE = 'certs/server_key.pem'

class SecureChatServer:
    def __init__(self):
        print(f"[*] Loading Server Certificate: {CERT_FILE}")
        self.cert_pem = read_file(CERT_FILE)
        self.key_pem = read_file(KEY_FILE)
        
    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(5)
        print(f"[*] Server listening on {HOST}:{PORT}")

        try:
            while True:
                conn, addr = server_sock.accept()
                print(f"[+] New connection from {addr}")
                threading.Thread(target=self.handle_client, args=(conn,)).start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server.")
            server_sock.close()

    def handle_client(self, conn):
        try:
            # 1. Receive Client Hello
            data = conn.recv(4096)
            if not data:
                return

            msg_dict = json.loads(data.decode('utf-8'))
            
            # validate it is a hello message
            hello = HelloMsg(**msg_dict)
            if hello.type != 'hello':
                raise ValueError("Expected hello message")

            print(f"[*] Received Hello from Client. Verifying Certificate...")
            
            # 2. Verify Client Certificate [cite: 162]
            # Expected CN is "client.local" (based on our generation script)
            if not verify_certificate(hello.client_cert, expected_cn="client.local"):
                print("[-] Client Certificate Verification FAILED. Closing.")
                conn.close()
                return

            print("[+] Client Authenticated.")

            # 3. Send Server Hello [cite: 68]
            resp = ServerHelloMsg(
                server_cert=self.cert_pem,
                nonce=generate_nonce()
            )
            conn.sendall(json.dumps(resp.model_dump()).encode('utf-8'))
            print("[*] Sent Server Hello.")
            
            # Keep connection open for next phase (Registration/Login)
            # For now, we just hold it to test connection
            # conn.close() 

        except Exception as e:
            print(f"[-] Error handling client: {e}")
            conn.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()