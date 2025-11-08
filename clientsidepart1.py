"""
clientsidepart1.py
Part 1: RSA-only client
- Encrypts and signs message using RSA.
"""
import socket, json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HOST = "127.0.0.1"
PORT = 65432

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
    text = input("Enter short message (Part1): ").encode()
    sig = sign(priv, text)
    pkg = make_package(text, sig)
    try:
        cipher = server_pub.encrypt(
            pkg,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
    except Exception as e:
        print("Message too long for RSA:", e)
        return
    payload = json.dumps({"ciphertext": base64.b64encode(cipher).decode()}).encode()
    send_payload(PORT, payload)
    print("[Part1] Sent encrypted message.")

if __name__ == "__main__":
    main()
