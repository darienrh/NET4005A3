import socket
import json
import base64
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

server_ip = "127.0.0.1"
server_port = 4444
# Functions to grab keys
def grab_my_private_key():
    """Get my private key file"""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    priv_key_file = "client_private_key.pem"
    try:
        with open(priv_key_file, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    except:
        print(f"Can't find {priv_key_file} - make sure it's in the same folder")
        raise
# grab server public key
def grab_server_pubkey():
    """Get server's public key"""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    # another hardcoded path
    pub_key_file = "server_public_key.pem"
    try:
        with open(pub_key_file, "rb") as f:
            return load_pem_public_key(f.read())
    except:
        print(f"Missing {pub_key_file} - get it from the server")
        raise

def to_b64(data):
    """Convert bytes to base64 string"""
    return base64.b64encode(data).decode('ascii')

def sign_my_message(my_priv_key, msg_data):
    """Sign the message"""
    # Using PSS because it's better than PKCS1
    signature = my_priv_key.sign(
        msg_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,  # max salt for security
        ),
        hashes.SHA256(),
    )
    return signature

def rsa_wrap_key(server_pubkey, aes_key):
    """Encrypt the AES key with server's RSA key"""
    # OAEP padding for security
    wrapped_key = server_pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped_key

def main():
    # Load keys - will crash if files missing
    my_priv_key = grab_my_private_key()
    server_pubkey = grab_server_pubkey()
    
    # Get what user wants to send
    user_msg = input("Type message to send: ").strip()
    if not user_msg:
        print("Type something!")
        return
        
    msg_bytes = user_msg.encode("utf-8")
    
    # Show what we're working with
    print(f"\nOK, your message is: '{user_msg}'")
    
    # Sign it first
    my_sig = sign_my_message(my_priv_key, msg_bytes)
    
    # Bundle it up with signature and timestamp
    msg_bundle = {
        "message": to_b64(msg_bytes),
        "signature": to_b64(my_sig),
        "sent_at": time.time()  # for replay protection on server
    }
    bundle_json = json.dumps(msg_bundle).encode('utf-8')
    
    # Make a random AES key and encrypt the bundle
    aes_key = os.urandom(32)  # 256-bit key
    nonce_val = os.urandom(12)  # GCM wants 12 bytes
    cipher = AESGCM(aes_key)
    encrypted_data = cipher.encrypt(nonce_val, bundle_json, None)
    
    # Show the encrypted version
    encrypted_b64 = to_b64(encrypted_data)
    print(f"Encrypted message: {encrypted_b64[:60]}...")  # show first part
    
    decrypted = cipher.decrypt(nonce_val, encrypted_data, None)
    unpacked = json.loads(decrypted.decode())
    original_msg = base64.b64decode(unpacked['message']).decode('utf-8')
    print(f"Decrypted back to: '{original_msg}'")
    
    # Encrypt the AES key for the server and send everything
    wrapped_aes_key = rsa_wrap_key(server_pubkey, aes_key)
    
    payload = {
        "mode": "part2",
        "enc_key": to_b64(wrapped_aes_key),
        "nonce": to_b64(nonce_val), 
        "ciphertext": encrypted_b64
    }
    
    # Try to send to server
    try:
        sock = socket.create_connection((server_ip, server_port), timeout=3.0)
        sock.sendall(json.dumps(payload).encode('utf-8'))
        sock.close()
        print("(Message sent to server)")
    except socket.timeout:
        print("(Server timeout - maybe it's not running?)")
    except ConnectionRefusedError:
        print("(Server refused connection - probably not running)")
    except Exception as e:
        print(f"(Failed to send: {e})")

if __name__ == "__main__":
    main()