from pydantic import BaseModel
from typing import Optional

# --- Control Plane Messages [cite: 66-71] ---

class HelloMsg(BaseModel):
    type: str = "hello"
    client_cert: str
    nonce: str

class ServerHelloMsg(BaseModel):
    type: str = "server hello"
    server_cert: str
    nonce: str

class RegisterMsg(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str    # Encrypted(salt || pwd)
    salt: str   # Base64 salt (sent in clear? PDF implies inside encryption, 
                # but for the outer wrapper we adhere to spec if distinct)
                # Note: PDF says Register msg contains 'salt' as a field [cite: 70]

class LoginMsg(BaseModel):
    type: str = "login"
    email: str
    pwd: str
    nonce: str

class AuthResponse(BaseModel):
    type: str = "auth_resp"
    status: str # "OK" or "FAIL"
    message: Optional[str] = None

# --- Key Agreement Messages [cite: 88-94] ---

class DHClientMsg(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int

class DHServerMsg(BaseModel):
    type: str = "dh_server"
    B: int

# --- Data Plane Messages [cite: 110] ---

class ChatMsg(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct: str     # Base64 Ciphertext
    sig: str    # Base64 Signature

# --- Non-Repudiation [cite: 132] ---

class SessionReceipt(BaseModel):
    type: str = "receipt"
    peer: str
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str