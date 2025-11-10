import socket
import json
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Config - would normally come from env or config file
HOST = "127.0.0.1" 
PORT = 4444
CLIENT_KEY_FILE = "client_private_key.pem"
SERVER_KEY_FILE = "server_public_key.pem"

def load_priv_key(path):
    """Load PEM private key - throws if file missing or invalid"""
    key_path = Path(path)
    if not key_path.exists():
        raise FileNotFoundError(f"Private key file {path} not found")
    
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)

def load_pub_key(path):
    """Load PEM public key - throws if file missing or invalid"""
    key_path = Path(path)
    if not key_path.exists():
        raise FileNotFoundError(f"Public key file {path} not found")
    
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())

def b64e(data):
    """Base64 encode bytes to string"""
    return base64.b64encode(data).decode('ascii')

def sign_msg(priv_key, msg_data):
    """Sign message using PSS padding - can throw on crypto errors"""
    # Using MAX_LENGTH for salt per our security reqs
    return priv_key.sign(
        msg_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_encrypt(pub_key, plain_data):
    """RSA encrypt using OAEP - can throw on crypto errors"""
    return pub_key.encrypt(
        plain_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():
    # Load crypto keys first - fail fast if missing
    try:
        priv_key = load_priv_key(CLIENT_KEY_FILE)
        pub_key = load_pub_key(SERVER_KEY_FILE)
    except Exception as e:
        print(f"FATAL: Failed to load keys - {e}", file=sys.stderr)
        sys.exit(1)

    # Get user input
    user_msg = input("Message to send: ").strip()
    if not user_msg:
        print("No message entered", file=sys.stderr)
        return
    
    msg_bytes = user_msg.encode('utf-8')
    
    try:
        # Sign the message
        sig = sign_msg(priv_key, msg_bytes)
        
        # Package and encrypt
        msg_pkg = {
            "msg": b64e(msg_bytes),
            "sig": b64e(sig)
        }
        json_data = json.dumps(msg_pkg).encode('utf-8')
        
        encrypted = rsa_encrypt(pub_key, json_data)
        
        # Prepare final payload
        payload = {
            "mode": "part1",
            "data": b64e(encrypted)
        }
        
        # Send over socket with timeout
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            sock.sendall(json.dumps(payload).encode('utf-8'))
            
            # Get response
            resp = sock.recv(4096).decode('utf-8')
            print(f"Got response: {resp}")
            
    except socket.timeout:
        print("Connection timed out", file=sys.stderr)
    except ConnectionRefusedError:
        print(f"Can't connect to {HOST}:{PORT}", file=sys.stderr)
    except Exception as e:
        print(f"Error during crypto or comms: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()