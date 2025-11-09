import socket, json, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 4444

def load_private_key(p):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(open(p, "rb").read(), password=None)

def load_public_key(p):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(open(p, "rb").read())

def ub64(s): return base64.b64decode(s.encode())

def rsa_decrypt(priv, ct):
    return priv.decrypt(
        ct,
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

    print("Server (Part 1) listening on port", PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            data = json.loads(conn.recv(65536).decode())
            enc = ub64(data["payload"])
            plain = rsa_decrypt(server_priv, enc)
            obj = json.loads(plain.decode())
            msg = base64.b64decode(obj["message"])
            sig = base64.b64decode(obj["signature"])

            if verify(client_pub, msg, sig):
                print("Verified message:", msg.decode())
                conn.sendall(b"Message verified and received.")
            else:
                conn.sendall(b"Signature verification failed.")
