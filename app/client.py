import socket
import json
import sys
from app.common.utils import read_file, generate_nonce
from app.common.protocol import HelloMsg, ServerHelloMsg
from app.crypto.pki import verify_certificate

from app.crypto.dh import DiffieHellman
from app.crypto.aes import AESCipher
from app.common.protocol import DHClientMsg, DHServerMsg, RegisterMsg, LoginMsg, AuthResponse

from app.crypto.pki import load_private_key
from app.crypto.sign import sign_data
from app.common.protocol import ChatMsg
from app.common.utils import now_ms

import base64

from app.storage.transcript import TranscriptManager # <--- Add this

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

    # --- Add this method to SecureChatClient class ---
    def chat_session(self, session_key):
        """
        Handles the user input loop for sending encrypted messages.
        """
        aes = AESCipher(session_key)
        
        # Load my private key for signing
        my_priv_key = load_private_key(KEY_FILE)

        # Initialize Transcript
        transcript = TranscriptManager(peer_name="server")
        
        seq_num = 1
        print("\n" + "="*40)
        print("SECURE CHAT STARTED (Type '/quit' to exit)")
        print("="*40)
        
        while True:
            msg_text = input("Me: ")
            if msg_text == '/quit':
                break
            
            # 1. Encrypt [cite: 204]
            # Convert str to bytes, then encrypt
            ct = aes.encrypt(msg_text.encode('utf-8'))
            
            # 2. Prepare Metadata
            ts = now_ms()
            
            # 3. Sign [cite: 207]
            # Signature over: seqno || ts || ct
            sig_payload = f"{seq_num}{ts}{ct}".encode('utf-8')
            signature = sign_data(my_priv_key, sig_payload)
            sig_b64 = base64.b64encode(signature).decode('utf-8')
            
            # 4. Send JSON [cite: 209]
            chat_msg = ChatMsg(
                type="msg",
                seqno=seq_num,
                ts=ts,
                ct=ct,
                sig=sig_b64
            )
            
            try:
                self.sock.sendall(json.dumps(chat_msg.model_dump()).encode('utf-8'))
                # --- LOG TO TRANSCRIPT ---
                transcript.add_entry(seq_num, ts, ct, sig_b64)
                seq_num += 1
            except Exception as e:
                print(f"[-] Send failed: {e}")
                break
        # --- GENERATE RECEIPT ON EXIT ---
        print("[*] Generating Session Receipt...")
        transcript.generate_receipt(my_priv_key)

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

        # --- 2. EPHEMERAL DH ---
        print("[*] Performing Ephemeral DH...")
        dh = DiffieHellman()
        dh_msg = DHClientMsg(type="dh_client", g=dh.g, p=dh.p, A=dh.get_public_key())
        self.sock.sendall(json.dumps(dh_msg.model_dump()).encode('utf-8'))
        
        data = self.sock.recv(4096)
        server_dh = DHServerMsg(**json.loads(data.decode('utf-8')))
        
        shared_secret = dh.compute_shared_secret(server_dh.B)
        k_temp_bytes = DiffieHellman.derive_session_key(shared_secret)
        aes_auth = AESCipher(k_temp_bytes)
        print(f"[+] Auth Key Established.")
        
        # --- 3. AUTHENTICATION ---
        while True:
            choice = input("1) Register\n2) Login\n> ")
            if choice == '1':
                email = input("Email: ")
                user = input("Username: ")
                pwd = input("Password: ")
                # Create Msg with RAW password (will be encrypted)
                # Note: We put empty salt/nonce for now as server handles it
                msg = RegisterMsg(type="register", email=email, username=user, pwd=pwd, salt="")
            elif choice == '2':
                email = input("Email: ")
                pwd = input("Password: ")
                msg = LoginMsg(type="login", email=email, pwd=pwd, nonce=generate_nonce())
            else:
                continue
            
            # Encrypt
            json_str = json.dumps(msg.model_dump())
            ct = aes_auth.encrypt(json_str.encode('utf-8'))
            wrapper = {"type": "auth_secure", "ct": ct}
            self.sock.sendall(json.dumps(wrapper).encode('utf-8'))
            
            # Receive Response
            data = self.sock.recv(4096)
            enc_resp = json.loads(data.decode('utf-8'))
            if enc_resp['type'] == 'auth_resp_enc':
                resp_bytes = aes_auth.decrypt(enc_resp['ct'])
                resp = AuthResponse(**json.loads(resp_bytes.decode('utf-8')))
                print(f"[*] Server: {resp.message}")
                if resp.status == "OK":
                    break
            else:
                print("[-] Invalid response")
                
        print("[+] Login Successful!")

        # --- PHASE 5: SESSION KEY AGREEMENT ---
        print("[*] Negotiating Session Key...")
        
        dh = DiffieHellman()
        dh_msg = DHClientMsg(type="dh_client", g=dh.g, p=dh.p, A=dh.get_public_key())
        self.sock.sendall(json.dumps(dh_msg.model_dump()).encode('utf-8'))
        
        data = self.sock.recv(4096)
        server_dh = DHServerMsg(**json.loads(data.decode('utf-8')))
        
        shared_secret = dh.compute_shared_secret(server_dh.B)
        session_key = DiffieHellman.derive_session_key(shared_secret)
        print(f"[+] Session Key Established.")
        
        # --- PHASE 6: ENTER CHAT ---
        self.chat_session(session_key)

if __name__ == "__main__":
    client = SecureChatClient()
    client.connect()