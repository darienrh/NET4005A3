"""
keymaker.py
Generates RSA 2048-bit keys for both client and server.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def make_keys(name_prefix: str):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{name_prefix}_private.pem", "wb") as f:
        f.write(priv_pem)
    with open(f"{name_prefix}_public.pem", "wb") as f:
        f.write(pub_pem)
    print(f"Generated {name_prefix}_private.pem / {name_prefix}_public.pem")

if __name__ == "__main__":
    make_keys("server")
    make_keys("client")
    print("All keys generated successfully.")
