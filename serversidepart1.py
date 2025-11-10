import socket
import json
import base64
import logging
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import threading
import time

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# logging setup
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger('msg_server')

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4444
SERVER_PRIV_KEY = "server_private_key.pem" 
CLIENT_PUB_KEY = "client_public_key.pem"
WORKER_THREADS = 8

class MessageServer:
    def __init__(self, host, port, workers=8):
        self.host = host
        self.port = port
        self.worker_count = workers
        self.thread_pool = None
        self.server_key = None
        self.client_pub = None
        self.current_connections = 0
        self.total_messages = 0
        
    def load_crypto_keys(self):
        """get RSA keys ready"""
        try:
            self.server_key = self.load_server_key(SERVER_PRIV_KEY)
            self.client_pub = self.load_client_pubkey(CLIENT_PUB_KEY)
            log.info("crypto keys are loaded and ready")
            return True
        except Exception as e:
            log.error(f"problem loading keys: {e}")
            return False

    def load_server_key(self, key_file_path):
        """load server private key"""
        key_file = Path(key_file_path)
        if not key_file.exists():
            raise FileNotFoundError(f"server key file not found: {key_file_path}")
            
        with open(key_file_path, "rb") as f:
            key_data = f.read()
            return load_pem_private_key(key_data, password=None)

    def load_client_pubkey(self, key_file_path):
        """load the client's public key for verification"""
        key_file = Path(key_file_path)
        if not key_file.exists():
            raise FileNotFoundError(f"client public key missing: {key_file_path}")
            
        with open(key_file_path, "rb") as f:
            key_data = f.read()
            return load_pem_public_key(key_data)

    def b64decode(self, encoded_data):
        """base64 decode helper"""
        return base64.b64decode(encoded_data)

    def rsa_decrypt_data(self, encrypted_data):
        """decrypt RSA encrypted data with our private key"""
        return self.server_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def aes_decrypt(self, key, iv, encrypted_data):
        """decrypt AES-CBC data"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_result = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # remove the padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        clean_data = unpadder.update(padded_result) + unpadder.finalize()
        
        return clean_data

    def check_signature(self, message_data, signature_data):
        """verify the message signature - runs in worker threads"""
        current_thread = threading.current_thread().name
        try:
            # simulate crypto processing time
            time.sleep(0.3)
            
            self.client_pub.verify(
                signature_data,
                message_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            log.info(f"signature looks good (thread: {current_thread})")
            return True
        except Exception as e:
            log.warning(f"bad signature detected (thread: {current_thread}): {e}")
            return False

    def process_message(self, raw_client_data, client_address):
        """handle a client message - runs in thread pool"""
        try:
            # parse what the client sent us
            client_msg = json.loads(raw_client_data.decode('utf-8'))
            
            # decrypt the session key first
            enc_session_key = self.b64decode(client_msg["enc_key"])
            session_key = self.rsa_decrypt_data(enc_session_key)
            
            # decrypt the actual message data
            iv_data = self.b64decode(client_msg["iv"])
            enc_message = self.b64decode(client_msg["data"])
            decrypted_payload = self.aes_decrypt(session_key, iv_data, enc_message)
            
            # unpack the message bundle
            message_package = json.loads(decrypted_payload.decode('utf-8'))
            original_msg = self.b64decode(message_package["msg"])
            msg_signature = self.b64decode(message_package["sig"])
            
            # verify the signature
            if self.check_signature(original_msg, msg_signature):
                log.info(f"got valid message from {client_address}: {original_msg.decode()}")
                self.total_messages += 1
                return True, f"OK: got your message '{original_msg.decode()}'"
            else:
                log.warning(f"signature check failed for {client_address}")
                return False, "ERROR: signature verification failed"
                
        except KeyError as e:
            log.error(f"missing field from {client_address}: {e}")
            return False, "ERROR: invalid message format"
        except json.JSONDecodeError as e:
            log.error(f"bad JSON from {client_address}: {e}")
            return False, "ERROR: invalid JSON"
        except Exception as e:
            log.error(f"error processing message from {client_address}: {e}")
            return False, f"ERROR: processing failed - {str(e)}"

    def handle_connection(self, conn, addr):
        """deal with a client connection"""
        client_ip = addr[0]
        self.current_connections += 1
        log.info(f"new connection from {client_ip} (total connections: {self.current_connections})")
        
        try:
            # get data from client
            data = conn.recv(65536)
            if not data:
                log.warning(f"empty data from {client_ip}")
                conn.sendall(b"Error: no data received")
                return
            
            # send to thread pool for processing
            future = self.thread_pool.submit(self.process_message, data, client_ip)
            
            # wait for result
            is_valid, response_text = future.result(timeout=25)
            
            # send back the result
            conn.sendall(response_text.encode('utf-8'))
            
        except socket.timeout:
            log.error(f"timeout processing message from {client_ip}")
            conn.sendall(b"ERROR: processing timeout")
        except Exception as e:
            log.error(f"connection issue with {client_ip}: {e}")
            conn.sendall(b"ERROR: connection problem")
        finally:
            self.current_connections -= 1
            log.info(f"closed connection from {client_ip} (remaining: {self.current_connections})")

    def run(self):
        """fire up the server"""
        log.info(f"starting server on {self.host}:{self.port}")
        
        if not self.load_crypto_keys():
            sys.exit(1)
        
        # setup thread pool for handling multiple clients
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.worker_count, 
            thread_name_prefix="worker"
        )
        
        # create server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)  # short timeout for clean shutdown
        
        try:
            sock.bind((self.host, self.port))
            sock.listen(15)  # decent backlog for multiple clients
            log.info(f"listening on port {self.port} with {self.worker_count} worker threads")
            log.info("ready for client connections...")
            
            while True:
                try:
                    client_conn, client_addr = sock.accept()
                    self.handle_connection(client_conn, client_addr)
                    
                except socket.timeout:
                    # just continue if timeout (allows interrupt checking)
                    continue
                except KeyboardInterrupt:
                    log.info("shutting down server...")
                    break
                except Exception as e:
                    log.error(f"problem accepting connection: {e}")
                    continue
                    
        except Exception as e:
            log.error(f"server socket error: {e}")
            return 1
        finally:
            # cleanup
            log.info("shutting down thread pool...")
            self.thread_pool.shutdown(wait=True)
            sock.close()
            log.info(f"server processed {self.total_messages} total messages")
            log.info("server shutdown complete")

def main():
    server = MessageServer(SERVER_HOST, SERVER_PORT, WORKER_THREADS)
    return server.run()

if __name__ == "__main__":
    exit(main())