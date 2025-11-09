import socket, json, base64, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 4444

def load_private_key(p):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(open(p, "rb").read(), password=None)

def load_public_key(p):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(open(p, "rb").read())

def b64(x): return base64.b64encode(x).decode()

def sign(priv, msg):
    return priv.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_encrypt(pub, data):
    return pub.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

if __name__ == "__main__":
    client_priv = load_private_key("client_private_key.pem")
    server_pub  = load_public_key("server_public_key.pem")

    msg = input("Enter message to send: ").encode()
    sig = sign(client_priv, msg)
    plain = json.dumps({"message": b64(msg), "signature": b64(sig)}).encode()

    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plain, None)
    enc_key = rsa_encrypt(server_pub, key)

    payload = {
        "mode": "part2",
        "enc_key": b64(enc_key),
        "nonce": b64(nonce),
        "ciphertext": b64(ct)
    }

    with socket.create_connection((HOST, PORT)) as s:
        s.sendall(json.dumps(payload).encode())
        print("[Client] Message sent securely. Waiting for encrypted server response")

        resp = json.loads(s.recv(4096).decode())
        reply_nonce = base64.b64decode(resp["nonce"])
        reply_ciphertext = base64.b64decode(resp["ciphertext"])
        reply_plain = AESGCM(key).decrypt(reply_nonce, reply_ciphertext, None)
        print("[Client] Secure reply from server:", reply_plain.decode())
