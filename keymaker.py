# keygen.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pathlib

def gen_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pathlib.Path(filename).write_bytes(pem)
    print(f"Saved {filename}")

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pathlib.Path(filename).write_bytes(pem)
    print(f"Saved {filename}")

if __name__ == "__main__":
    s_priv, s_pub = gen_rsa_keypair()
    save_private_key(s_priv, "server_private_key.pem")
    save_public_key(s_pub, "server_public_key.pem")

    c_priv, c_pub = gen_rsa_keypair()
    save_private_key(c_priv, "client_private_key.pem")
    save_public_key(c_pub, "client_public_key.pem")

    print("All RSA keys generated successfully.")
