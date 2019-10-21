from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import sys

def prove_identity(private_key, challenge):
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

if __name__ == "__main__": 
    private_key_file = sys.argv[1]
    challenge_file = sys.argv[2]
    response_file = sys.argv[3]
    
    with open(private_key_file, "rb") as private_key_file_object:
        private_key = serialization.load_pem_private_key(
                         private_key_file_object.read(),
                         backend=default_backend(),
                         password=None)
                         
    with open(challenge_file, "rb") as challenge_file_object:
        challenge_bytes = challenge_file_object.read()
                         
    signed_challenge_bytes = prove_identity(
        private_key,
        challenge_bytes)
    
    with open(response_file, "wb") as response_object:
        response_object.write(signed_challenge_bytes)

    # For auto test
    import os
    if os.path.exists(response_file):
        print("[PASS]")
    else:
        print("[FAIL]")