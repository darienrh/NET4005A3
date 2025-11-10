import socket
import json
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os

# connection settings
HOST = "127.0.0.1" 
PORT = 4444
CLIENT_PRIV_KEY = "client_private_key.pem"
SERVER_PUB_KEY = "server_public_key.pem"

def get_private_key(key_path):
    """grab our private key file"""
    key_file = Path(key_path)
    if not key_file.exists():
        raise FileNotFoundError(f"can't find private key at {key_path}")
    
    with open(key_path, "rb") as f:
        key_data = f.read()
        return load_pem_private_key(key_data, password=None)

def get_public_key(key_path):
    """load up a public key"""
    key_file = Path(key_path)
    if not key_file.exists():
        raise FileNotFoundError(f"public key missing: {key_path}")
    
    with open(key_path, "rb") as f:
        key_data = f.read()
        return load_pem_public_key(key_data)

def to_base64(data):
    """convert bytes to base64 string"""
    return base64.b64encode(data).decode('ascii')

def create_signature(priv_key, message_data):
    """sign the message with our private key"""
    return priv_key.sign(
        message_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_encrypt_data(pub_key, data):
    """encrypt with RSA using OAEP"""
    return pub_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(key, plaintext):
    """encrypt data with AES-CBC"""
    # random IV for this encryption
    iv = os.urandom(16)
    
    # pad the data to block size
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # do the encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv, ciphertext

def main():
    try:
        client_priv = get_private_key(CLIENT_PRIV_KEY) # load our private key
        server_pub = get_public_key(SERVER_PUB_KEY)
    except Exception as err:
        print(f"Failed loading keys: {err}", file=sys.stderr)
        sys.exit(1)

    
    user_input = input("Enter your message: ").strip() #this gets user input
    if not user_input:
        print("no message provided", file=sys.stderr)
        return
    
    message_data = user_input.encode('utf-8')
    
    try:
        # sign the message with our private key
        signature = create_signature(client_priv, message_data)
        
        # make a random AES key for this session
        session_key = os.urandom(32) # this will make a random aes key
        
        # bundle up the message and signature
        message_bundle = {
            "msg": to_base64(message_data),
            "sig": to_base64(signature)
        }
        bundle_json = json.dumps(message_bundle).encode('utf-8')
        
        # encrypt the bundle with AES
        iv, encrypted_bundle = aes_encrypt(session_key, bundle_json)
        
        encrypted_session_key = rsa_encrypt_data(server_pub, session_key)# this will encrypt the message with the session key

        
        # final payload to send
        payload = {
            "enc_key": to_base64(encrypted_session_key),
            "iv": to_base64(iv),
            "data": to_base64(encrypted_bundle)
        }
        
        # connect and send the data
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            sock.sendall(json.dumps(payload).encode('utf-8'))
            
            # wait for server response
            response = sock.recv(4096).decode('utf-8')
            print(f"Server says: {response}")
            
    except socket.timeout:
        print("connection timed out", file=sys.stderr)
    except ConnectionRefusedError:
        print(f"cannot reach server at {HOST}:{PORT}", file=sys.stderr)
    except Exception as err:
        print(f"something went wrong: {err}", file=sys.stderr)
        # helpful for debugging but might remove in production
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()