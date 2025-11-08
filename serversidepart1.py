"""
serversidepart1.py
Part 1: RSA-only server
- Decrypts entire message using server private key.
- Verifies client signature using client public key.
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

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        pkt = conn.recv(n - len(data))
        if not pkt:
            return None
        data += pkt
    return data

def verify_sig(pub, msg, sig):
    try:
        pub.verify(
            sig, msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def parse_plain(plaintext):
    ln = int.from_bytes(plaintext[:4], "big")
    msg = plaintext[4:4+ln]
    sig = plaintext[4+ln:]
    return msg, sig

def main():
    priv = load_priv("server_private.pem")
    client_pub = load_pub("client_public.pem")
    with socket.socket() as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Part1] Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[Part1] Connection from {addr}")
                length = recv_exact(conn, 8)
                if not length: continue
                size = int.from_bytes(length, "big")
                payload = recv_exact(conn, size)
                if not payload: continue
                data = json.loads(payload.decode())
                cipher = base64.b64decode(data["ciphertext"])
                try:
                    plain = priv.decrypt(
                        cipher,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                     algorithm=hashes.SHA256(),
                                     label=None)
                    )
                except Exception as e:
                    print("Decryption error:", e)
                    continue
                msg, sig = parse_plain(plain)
                if verify_sig(client_pub, msg, sig):
                    print("Signature verified ✓")
                    print("Message:", msg.decode(errors="replace"))
                else:
                    print("Signature failed ✗")

if __name__ == "__main__":
    main()
