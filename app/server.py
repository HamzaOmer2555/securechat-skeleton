import socket
import json
import threading
import sys
from app.common.utils import read_file, generate_nonce
from app.common.protocol import HelloMsg, ServerHelloMsg
from app.crypto.pki import verify_certificate
import os

import base64
from app.crypto.dh import DiffieHellman
from app.crypto.aes import AESCipher
from app.common.protocol import DHClientMsg, DHServerMsg, RegisterMsg, LoginMsg, AuthResponse
from app.storage import db

from app.crypto.pki import load_private_key
from app.crypto.sign import verify_signature, load_public_key
from app.common.protocol import ChatMsg
from app.common.utils import now_ms

from app.crypto.pki import load_certificate  # <--- FIXED: Added load_certificate

from app.storage.transcript import TranscriptManager # <--- Add this

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

    def chat_loop(self, conn, session_key, client_cert_pem):
        """
        Handles the encrypted chat session.
        """
        aes = AESCipher(session_key)
        
        # FIX: Extract public key from the certificate object
        # The previous error happened because we tried to load a Cert as a Key
        cert_obj = load_certificate(client_cert_pem.encode('utf-8'))
        client_pub_key = cert_obj.public_key()
        
        # Load my private key for signing (not strictly used if we only receive, but good for replies)
        my_priv_key = load_private_key(KEY_FILE)

        # Initialize Transcript
        transcript = TranscriptManager(peer_name="client")
        
        # State
        peer_seq = 0
        
        print("[*] Entering Secure Chat Loop. (Ctrl+C to stop server log)")
        
        try:
            while True:
                # 1. Receive Message
                data = conn.recv(4096)
                if not data: break
                
                msg_dict = json.loads(data.decode('utf-8'))
                
                if msg_dict.get('type') != 'msg':
                    print(f"[-] Unknown message type: {msg_dict.get('type')}")
                    continue
                    
                chat_msg = ChatMsg(**msg_dict)
                
                # 2. Replay Protection
                if chat_msg.seqno <= peer_seq:
                    print(f"[-] REPLAY DETECTED: Msg seq {chat_msg.seqno} <= {peer_seq}")
                    continue 
                peer_seq = chat_msg.seqno
                
                # 3. Verify Signature
                # We reconstruct the payload: seqno + ts + ct
                verify_data = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode('utf-8')
                
                try:
                    verify_signature(client_pub_key, verify_data, base64.b64decode(chat_msg.sig))
                except Exception as e:
                    print(f"[-] SIG_FAIL: Signature verification failed! {e}")
                    continue
                
                transcript.add_entry(chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig)

                # 4. Decrypt
                try:
                    plaintext = aes.decrypt(chat_msg.ct)
                    print(f"> Client: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"[-] Decryption failed: {e}")

        except Exception as e:
            print(f"[-] Chat Error: {e}")
        finally:
            # --- GENERATE RECEIPT ON DISCONNECT ---
            print("[*] Client disconnected. Generating Receipt...")
            transcript.generate_receipt(my_priv_key)

    def handle_client(self, conn):
        try:
            # --- 1. HANDSHAKE (Hello) ---
            data = conn.recv(4096)
            if not data: return
            msg_dict = json.loads(data.decode('utf-8'))
            hello = HelloMsg(**msg_dict)
            
            if not verify_certificate(hello.client_cert, expected_cn="client.local"):
                print("[-] Client Cert Verification Failed")
                conn.close()
                return
            
            client_cert = hello.client_cert 
            
            resp = ServerHelloMsg(server_cert=self.cert_pem, nonce=generate_nonce())
            conn.sendall(json.dumps(resp.model_dump()).encode('utf-8'))
            
            # --- 2. EPHEMERAL DH (For Auth Encryption) ---
            print("[*] Starting Ephemeral DH for Auth...")
            data = conn.recv(4096)
            client_dh_msg = DHClientMsg(**json.loads(data.decode('utf-8')))
            dh = DiffieHellman(p=client_dh_msg.p, g=client_dh_msg.g)
            server_dh_msg = DHServerMsg(type="dh_server", B=dh.get_public_key())
            conn.sendall(json.dumps(server_dh_msg.model_dump()).encode('utf-8'))
            
            shared_secret = dh.compute_shared_secret(client_dh_msg.A)
            k_temp_bytes = DiffieHellman.derive_session_key(shared_secret)
            aes_auth = AESCipher(k_temp_bytes)
            
            # --- 3. AUTHENTICATION ---
            authenticated = False
            user_email = ""
            
            while not authenticated:
                data = conn.recv(8192)
                if not data: return
                try:
                    enc_wrapper = json.loads(data.decode('utf-8'))
                    if enc_wrapper.get('type') != 'auth_secure': 
                        print("[-] Unexpected auth packet")
                        return
                    
                    json_bytes = aes_auth.decrypt(enc_wrapper['ct'])
                    inner_msg = json.loads(json_bytes.decode('utf-8'))
                    
                    resp = None
                    if inner_msg['type'] == 'register':
                        print(f"[*] Registering: {inner_msg['username']}")
                        salt_bytes = os.urandom(16)
                        salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
                        pwd_hash = db.hash_password(salt_bytes, inner_msg['pwd'])
                        
                        if db.add_user(inner_msg['email'], inner_msg['username'], salt_b64, pwd_hash):
                            resp = AuthResponse(status="OK", message="Registered Successfully")
                        else:
                            resp = AuthResponse(status="FAIL", message="Username or Email already exists")
                            
                    elif inner_msg['type'] == 'login':
                        print(f"[*] Login attempt: {inner_msg['email']}")
                        user = db.get_user_by_email(inner_msg['email']) 
                        if user:
                            # user: (email, username, salt_blob, pwd_hash)
                            salt_bytes = user[2]
                            stored_hash = user[3]
                            computed_hash = db.hash_password(salt_bytes, inner_msg['pwd'])
                            if computed_hash == stored_hash:
                                authenticated = True
                                user_email = user[0]
                                resp = AuthResponse(status="OK", message="Login Success")
                            else:
                                resp = AuthResponse(status="FAIL", message="Invalid Credentials")
                        else:
                            resp = AuthResponse(status="FAIL", message="User not found")
                    
                    resp_bytes = json.dumps(resp.model_dump()).encode('utf-8')
                    ct = aes_auth.encrypt(resp_bytes)
                    conn.sendall(json.dumps({"type": "auth_resp_enc", "ct": ct}).encode('utf-8'))
                    
                except Exception as e:
                    print(f"[-] Auth Error: {e}")
                    import traceback
                    traceback.print_exc()
                    return

            print(f"[+] User {user_email} Authenticated.")

            # --- 4. SESSION KEY AGREEMENT ---
            print("[*] Establishing Session Key...")
            data = conn.recv(4096)
            client_dh_sess = DHClientMsg(**json.loads(data.decode('utf-8')))
            
            dh_sess = DiffieHellman(p=client_dh_sess.p, g=client_dh_sess.g)
            server_dh_sess = DHServerMsg(type="dh_server", B=dh_sess.get_public_key())
            conn.sendall(json.dumps(server_dh_sess.model_dump()).encode('utf-8'))
            
            shared_secret_sess = dh_sess.compute_shared_secret(client_dh_sess.A)
            session_key = DiffieHellman.derive_session_key(shared_secret_sess)
            print(f"[+] Session Key Established: {session_key.hex()[:8]}...")
            
            # --- 5. CHAT LOOP ---
            self.chat_loop(conn, session_key, client_cert)
            
            conn.close()

        except Exception as e:
            print(f"[-] Error: {e}")
            conn.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()