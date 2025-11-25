import hashlib
import json
import base64
import os
from app.common.protocol import SessionReceipt
from app.crypto.sign import sign_data

class TranscriptManager:
    def __init__(self, peer_name):
        self.peer_name = peer_name
        self.entries = []
        self.first_seq = None
        self.last_seq = None
        
    def add_entry(self, seqno, ts, ct, sig):
        """
        Logs a message entry.
        Format: seqno | ts | ct | sig 
        """
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # The line format impacts the hash, so it must be consistent on both sides.
        # We use a pipe-delimited string as described in PDF (conceptually).
        # To be safe, we'll store the exact string we want to hash.
        entry_str = f"{seqno}|{ts}|{ct}|{sig}"
        self.entries.append(entry_str)
        
    def compute_transcript_hash(self) -> str:
        """
        Computes SHA256 over the concatenation of all transcript lines.
        """
        full_log = "\n".join(self.entries)
        return hashlib.sha256(full_log.encode('utf-8')).hexdigest()
        
    def generate_receipt(self, my_private_key, output_dir="transcripts"):
        """
        Signs the transcript hash and saves the receipt to disk.
        """
        if not self.entries:
            print("[-] No entries to generate receipt.")
            return

        tx_hash = self.compute_transcript_hash()
        
        # Sign the hash
        signature = sign_data(my_private_key, tx_hash.encode('utf-8'))
        sig_b64 = base64.b64encode(signature).decode('utf-8')
        
        receipt = SessionReceipt(
            type="receipt",
            peer=self.peer_name,
            first_seq=self.first_seq,
            last_seq=self.last_seq,
            transcript_sha256=tx_hash,
            sig=sig_b64
        )
        
        # Save to file
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{output_dir}/receipt_{self.peer_name}_{self.last_seq}.json"
        
        with open(filename, 'w') as f:
            f.write(json.dumps(receipt.model_dump(), indent=4))
            
        print(f"[+] Session Receipt generated: {filename}")