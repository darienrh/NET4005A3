"""
clientsidepart2.py
Part 2: Hybrid AES-GCM client
- Encrypts message with AES-GCM.
- Encrypts AES key with server's RSA public key.
"""
import socket, json, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 65433

def load_priv(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)

def load_pub(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def send_payload(port, data):
    with socket.socket() as s:
        s.connect((HOST, port))
        s.sendall(len(data).to_bytes(8, "big"))
        s.sendall(data)

def make_package(msg, sig):
    return len(msg).to_bytes(4, "big") + msg + sig

def sign(priv, msg):
    return priv.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def main():
    priv = load_priv("client_private.pem")
    server_pub = load_pub("server_public.pem")
    text = input("Enter message (Part2): ").encode()
    sig = sign(priv, text)
    pkg = make_package(text, sig)

    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    cipher = aes.encrypt(nonce, pkg, None)

    enc_key = server_pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    obj = {
        "enc_key": base64.b64encode(enc_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(cipher).decode()
    }
    payload = json.dumps(obj).encode()
    send_payload(PORT, payload)
    print("[Part2] Sent hybrid-encrypted message.")

if __name__ == "__main__":
    main()
