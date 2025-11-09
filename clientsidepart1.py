import socket, json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HOST = "127.0.0.1"
PORT = 4444

def load_private_key(path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(open(path, "rb").read(), password=None)

def load_public_key(path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(open(path, "rb").read())

def b64(x): return base64.b64encode(x).decode()

def sign_message(priv, msg):
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

    message = input("Enter message to send: ").encode()
    signature = sign_message(client_priv, message)

    pkg = json.dumps({"message": b64(message), "signature": b64(signature)}).encode()
    encrypted = rsa_encrypt(server_pub, pkg)
    payload = {"mode": "part1", "payload": b64(encrypted)}

    with socket.create_connection((HOST, PORT)) as s:
        s.sendall(json.dumps(payload).encode())
        print("Response:", s.recv(4096).decode())
