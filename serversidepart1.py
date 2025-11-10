import socket
import json
import base64
import logging
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Setup basic logging for ops team
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('msg_server')

# TODO: Move to config file for prod
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4444
PRIV_KEY_PATH = "server_private_key.pem" 
PUB_KEY_PATH = "client_public_key.pem"

def load_priv_key(key_path):
    """Load server's RSA private key for decrypting client messages"""
    try:
        key_file = Path(key_path)
        if not key_file.exists():
            logger.error(f"Key file missing: {key_path}")
            raise FileNotFoundError(f"Private key not found at {key_path}")
            
        with open(key_path, "rb") as f:
            key_data = f.read()
            return load_pem_private_key(key_data, password=None)
    except Exception as e:
        logger.error(f"Failed loading private key: {e}")
        raise

def load_pub_key(key_path):
    """Load client's public RSA key for signature verification"""
    try:
        key_file = Path(key_path)
        if not key_file.exists():
            logger.error(f"Public key file missing: {key_path}")
            raise FileNotFoundError(f"Public key not found at {key_path}")
            
        with open(key_path, "rb") as f:
            key_data = f.read()
            return load_pem_public_key(key_data)
    except Exception as e:
        logger.error(f"Failed loading public key: {e}")
        raise

def b64_decode(encoded_str):
    """Base64 decode wrapper with error handling"""
    try:
        return base64.b64decode(encoded_str.encode('ascii'))
    except Exception as e:
        logger.error(f"Base64 decode failed: {e}")
        raise

def rsa_decrypt(private_key, ciphertext):
    """Decrypt RSA-OAEP encrypted data - used for client session keys"""
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        logger.error(f"RSA decrypt failed: {e}")
        raise

def verify_signature(public_key, message_bytes, signature_bytes):
    """Verify message signature using RSA-PSS - returns bool for auth result"""
    try:
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH  # Max security for our use case
            ),
            hashes.SHA256()
        )
        logger.info("Signature verification passed")
        return True
    except Exception as e:
        logger.warning(f"Signature verification failed: {e}")
        return False

def handle_client_connection(conn, addr, server_private_key, client_public_key):
    """Process incoming client message with auth and decrypt"""
    client_ip = addr[0]
    logger.info(f"New connection from {client_ip}")
    
    try:
        # Receive and parse client data
        raw_data = conn.recv(65536)
        if not raw_data:
            logger.warning(f"No data received from {client_ip}")
            conn.sendall(b"Error: No data received")
            return
            
        client_request = json.loads(raw_data.decode('utf-8'))
        
        # Decrypt the main payload
        encrypted_payload = b64_decode(client_request["payload"])
        decrypted_data = rsa_decrypt(server_private_key, encrypted_payload)
        
        # Parse the decrypted message package
        message_package = json.loads(decrypted_data.decode('utf-8'))
        original_message = base64.b64decode(message_package["message"])
        message_signature = base64.b64decode(message_package["signature"])
        
        # Verify message authenticity
        if verify_signature(client_public_key, original_message, message_signature):
            logger.info(f"Verified message from {client_ip}: {original_message.decode()}")
            conn.sendall(b"OK: Message verified and processed")
        else:
            logger.warning(f"Invalid signature from {client_ip}")
            conn.sendall(b"ERROR: Signature verification failed")
            
    except KeyError as e:
        logger.error(f"Missing field in request from {client_ip}: {e}")
        conn.sendall(b"ERROR: Invalid request format")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON from {client_ip}: {e}")
        conn.sendall(b"ERROR: Invalid JSON data")
    except Exception as e:
        logger.error(f"Unexpected error handling {client_ip}: {e}")
        conn.sendall(b"ERROR: Server processing error")

def main():
    """Main server loop - loads keys and listens for client connections"""
    logger.info(f"Starting message server on {SERVER_HOST}:{SERVER_PORT}")
    
    # Load crypto keys first
    try:
        server_priv = load_priv_key(PRIV_KEY_PATH)
        client_pub = load_pub_key(PUB_KEY_PATH)
        logger.info("Crypto keys loaded successfully")
    except Exception as e:
        logger.error(f"Failed to initialize server: {e}")
        sys.exit(1)
    
    # Setup server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(5)
        logger.info(f"Server listening on port {SERVER_PORT}")
        
        while True:
            try:
                conn, addr = server_socket.accept()
                with conn:
                    handle_client_connection(conn, addr, server_priv, client_pub)
            except KeyboardInterrupt:
                logger.info("Server shutdown requested")
                break
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Server socket error: {e}")
        return 1
    finally:
        server_socket.close()
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    exit(main())