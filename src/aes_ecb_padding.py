# NEVER USE: ECB is not secure!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Alice and Bob's Shared Key
test_key = bytes.fromhex('00112233445566778899AABBCCDDEEFF')

aesCipher = Cipher(algorithms.AES(test_key),
                   modes.ECB(),
                   backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

message = b"""
FROM: FIELD AGENT ALICE
TO: FIELD AGENT BOB
RE: Meeting
DATE: 2001-1-1

Meet me today at the docks at 2300."""

message += b"E" * (-len(message) % 16)
ciphertext = aesEncryptor.update(message)

print("plaintext:",message)
print("ciphertext:",ciphertext.hex())
recovered = aesDecryptor.update(ciphertext)
print("recovered:",recovered)
if(message==recovered): print("[PASS]")
else: print("[FAIL]")