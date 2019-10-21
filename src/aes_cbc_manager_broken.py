from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class EncryptionManager:
    def __init__(self):
        self.key = os.urandom(32)
        self.iv  = os.urandom(16)

    def encrypt_message(self, message):
        # WARNING: This code is not secure!!
        encryptor = Cipher(algorithms.AES(self.key),
                           modes.CBC(self.iv),
                           backend=default_backend()).encryptor()
        padder = padding.PKCS7(128).padder()

        padded_message = padder.update(message)
        padded_message += padder.finalize()
        ciphertext = encryptor.update(padded_message)
        ciphertext += encryptor.finalize()
        return ciphertext

    def decrypt_message(self, ciphertext):
        # WARNING: This code is not secure!!
        decryptor = Cipher(algorithms.AES(self.key),
                           modes.CBC(self.iv),
                           backend=default_backend()).decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        padded_message = decryptor.update(ciphertext)
        padded_message += decryptor.finalize()
        message = unpadder.update(padded_message)
        message += unpadder.finalize()
        return message

# Automatically generate key/IV for encryption.
manager = EncryptionManager()

plaintexts = [
    b"SHORT",
    b"MEDIUM MEDIUM MEDIUM",
    b"LONG LONG LONG LONG LONG LONG"
]

ciphertexts = []

for m in plaintexts:
    ciphertexts.append(manager.encrypt_message(m))

for c in ciphertexts:
    print("Recovered", manager.decrypt_message(c))

test_manager = EncryptionManager()
c1 = test_manager.encrypt_message(b'AAAAAAAAAAAAAAAA')
c2 = test_manager.encrypt_message(b'AAAAAAAAAAAAAAAA')
print(c1.hex(), c2.hex())
c3 = bytes([a ^ b for a, b  in zip(c1, c2)])
print(c3.hex())

if c1 == c2 and c3 == b"\x00"*len(c1):
    print("[PASS]")
else:
    print("[FAIL]")