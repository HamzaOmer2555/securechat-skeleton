import time
import os
import hashlib
import base64

def now_ms() -> int:
    """Returns current Unix timestamp in milliseconds."""
    return int(time.time() * 1000)

def generate_nonce(length=16) -> str:
    """Generates a random nonce encoded in Base64."""
    return base64.b64encode(os.urandom(length)).decode('utf-8')

def read_file(path: str) -> str:
    """Reads a text file and returns content (e.g., for loading PEMs)."""
    with open(path, 'r') as f:
        return f.read()