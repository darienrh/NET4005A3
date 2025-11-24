# NET4005A3

OVERVIEW:
----------------------------------------------
this file implements a messaging system with 2 parts
part 1 which is asymettric and part 2 which si synchronous

CLIENT FILES:
clientsidepart1 - is for part 1
clientsidepart2 - is for part 2

SERVER FILES:
serversidepart1 - part 1
serversidepart2 - part 2

KEY FILES:
client_private_key.pem - Client's RSA private key (for signing)
client_public_key.pem  - Clients' RSA public key (for verification)
server_private_key.pem - Server's RSA private key (for decryption)  
server_public_key.pem  - Server's RSA public key (for encryption)

PREREQUISITES:
1. Python 3.8+ MUST be installed
2. cryptography library installed if not: use "pip install cryptography"
3. All 4 key files must be generated and present in the same directory

GENERATING KEYS: 
run python .\keymaker.py if the keys arent showing up or are deleted

TESTING PART 1 (ASYMMETRIC ONLY):

1. Start the server:
   run python .\serversidepart2.py
   
2. In a separate terminal, run the client:
    run python .\clientsidepart1.py
   
3. Enter a message when prompted
   
4. Observe both server logs and client response

TESTING PART 2 (HYBRID ENCRYPTION):

1. Start the server (same as above):
    run python .\serversidepart2.py
   
2. In a separate terminal, run the client:
    run python .\clientsidepart2.py
   
3. Enter a message when prompted

4. Observe server logs both and encrypted response

EXPECTED BEHAVIOR:

PART 1:
Client: Message -> Sign -> RSA encrypt -> Send
Server: RSA decrypt -> Verify signature -> Plaintext response

PART 2:  
Client: Message -> Sign -> AES encrypt -> RSA encrypt key -> Send both
Server: RSA decrypt key -> AES decrypt -> Verify signature -> Encrypted response

NOTES:
The serversidepart2.py can handle both Part 1 and Part 2 clients
Server runs on localhost:4444 by default

AUTHOR: Darien R-H
DATE: 2025-11-09
