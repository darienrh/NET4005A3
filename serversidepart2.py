import socket
import json
import base64
import os
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('secure_server')

HOST = "127.0.0.1"
PORT = 4444

def load_private_key(path):
    """Load the server's private key"""
    try:
        with open(path, 'rb') as f:
            key_data = f.read()
        return load_pem_private_key(key_data, password=None)
    except Exception as e:
        logger.error(f"Failed to load private key from {path}: {e}")
        raise

def load_public_key(path):
    """Load the client's public key"""
    try:
        with open(path, 'rb') as f:
            key_data = f.read()
        return load_pem_public_key(key_data)
    except Exception as e:
        logger.error(f"Failed to load public key from {path}: {e}")
        raise

def b64_decode(encoded_str):
    """Decode base64 string to bytes"""
    return base64.b64decode(encoded_str.encode())

def rsa_decrypt(private_key, encrypted_data):
    """Decrypt RSA encrypted data using OAEP padding"""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def verify_signature(public_key, message, signature):
    """Verify the message signature using PSS padding"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # Use SHA-256 for hashing
        )
        return True
    except Exception as e:
        logger.warning(f"Signature verification failed: {e}")
        return False

def handle_client(conn, addr, server_priv, client_pub):
    """Handle a single client connection"""
    client_ip = addr[0]
    logger.info(f"Handling connection from {client_ip}")
    
    try:
        # Receive the client data
        data = conn.recv(65536).decode('utf-8')
        if not data:
            logger.warning(f"No data received from {client_ip}")
            return
        
        # Parse the JSON payload
        payload = json.loads(data)
        
        # Extract and decrypt the session key
        encrypted_key = b64_decode(payload['enc_key'])
        session_key = rsa_decrypt(server_priv, encrypted_key)
        
        # Get the encrypted message components
        nonce = b64_decode(payload['nonce'])
        ciphertext = b64_decode(payload['ciphertext'])
        
        # Decrypt the main message
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse the decrypted message
        message_obj = json.loads(plaintext.decode('utf-8'))
        original_message = base64.b64decode(message_obj['message'])
        signature = base64.b64decode(message_obj['signature'])
        
        # Verify the signature
        if verify_signature(client_pub, original_message, signature):
            logger.info(f"Successfully verified message from {client_ip}: {original_message.decode()}")
            
            # Send encrypted response
            response_nonce = os.urandom(12)
            response_text = b"Server received your message. Signature verified OK."
            response_ciphertext = aesgcm.encrypt(response_nonce, response_text, None)
            
            response = {
                'nonce': base64.b64encode(response_nonce).decode(),
                'ciphertext': base64.b64encode(response_ciphertext).decode()
            }
            
            conn.sendall(json.dumps(response).encode())
            logger.info(f"Sent encrypted response to {client_ip}")
            conn.shutdown(socket.SHUT_WR)
            
        else:
            logger.warning(f"Invalid signature from {client_ip}")
            # Still send an encrypted response but with error
            response_nonce = os.urandom(12)
            response_text = b"ERROR: Signature verification failed"
            response_ciphertext = AESGCM(session_key).encrypt(response_nonce, response_text, None)
            
            response = {
                'nonce': base64.b64encode(response_nonce).decode(),
                'ciphertext': base64.b64encode(response_ciphertext).decode()
            }
            conn.sendall(json.dumps(response).encode())
            
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON from {client_ip}: {e}")
        conn.sendall(b"Invalid JSON format")
    except KeyError as e:
        logger.error(f"Missing field in request from {client_ip}: {e}")
        conn.sendall(b"Missing required fields")
    except Exception as e:
        logger.error(f"Error handling client {client_ip}: {e}")
        # Don't send sensitive error details to client
        conn.sendall(b"Server error occurred")
    finally:
        logger.info(f"End of handle_client() reached for {client_ip}")
        logger.info(f"Closed connection with {client_ip}")

def main():
    """Main server loop"""
    logger.info("Starting secure message server...")
    
    try:
        # Load our keys
        server_private = load_private_key("server_private_key.pem")
        client_public = load_public_key("client_public_key.pem")
        logger.info("Keys loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load keys: {e}")
        return 1
    
    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"Server listening on {HOST}:{PORT}")
        
        while True:
            try:
                conn, addr = server_socket.accept()
                with conn:
                    handle_client(conn, addr, server_private, client_public)
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, shutting down...")
                break
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Server error: {e}")
        return 1
    finally:
        server_socket.close()
        logger.info("Server shut down")
    
    return 0

if __name__ == "__main__":
    exit(main())