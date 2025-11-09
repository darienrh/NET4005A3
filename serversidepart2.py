# serversidepart2.py
import socket, json, base64, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 4444

def load_private_key(p):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(open(p, "rb").read(), password=None)

def load_public_key(p):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(open(p, "rb").read())

def ub64(s): return base64.b64decode(s.encode())

def rsa_decrypt(priv, data):
    return priv.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def verify(pub, msg, sig):
    try:
        pub.verify(
            sig, msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    server_priv = load_private_key("server_private_key.pem")
    client_pub  = load_public_key("client_public_key.pem")

    print("Server (Part 2) listening on port", PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            data = json.loads(conn.recv(65536).decode())
            key = rsa_decrypt(server_priv, ub64(data["enc_key"]))
            nonce = ub64(data["nonce"])
            ciphertext = ub64(data["ciphertext"])

            plain = AESGCM(key).decrypt(nonce, ciphertext, None)
            obj = json.loads(plain.decode())
            msg = base64.b64decode(obj["message"])
            sig = base64.b64decode(obj["signature"])

            if verify(client_pub, msg, sig):
                print("Verified message:", msg.decode())
                if verify(client_pub, msg, sig):
                    print("[Server] Message and signature verified successfully.")

                    # Encrypt a reply using the same AES key and nonce (but safer to use a new nonce)
                    reply_nonce = os.urandom(12)
                    reply_text = b"Message verified and received securely (Part 2, bidirectional)."
                    reply_ciphertext = AESGCM(key).encrypt(reply_nonce, reply_text, None)

                    response_payload = {
                        "nonce": base64.b64encode(reply_nonce).decode(),
                        "ciphertext": base64.b64encode(reply_ciphertext).decode()
                    }
                    conn.sendall(json.dumps(response_payload).encode())
                else:
                    reply_nonce = os.urandom(12)
                    reply_text = b"Signature verification failed."
                    reply_ciphertext = AESGCM(key).encrypt(reply_nonce, reply_text, None)

                    response_payload = {
                        "nonce": base64.b64encode(reply_nonce).decode(),
                        "ciphertext": base64.b64encode(reply_ciphertext).decode()
                    }
                    conn.sendall(json.dumps(response_payload).encode())
            else:
                conn.sendall(b"Signature verification failed.")
