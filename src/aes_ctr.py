from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class EncryptionManager:
    def __init__(self):
        key = os.urandom(32)
        nonce = os.urandom(16)
        aes_context = Cipher(algorithms.AES(key),
                            modes.CTR(nonce),
                            backend=default_backend())
        self.encryptor = aes_context.encryptor()
        self.decryptor = aes_context.decryptor()

    def updateEncryptor(self, plaintext):
        return self.encryptor.update(plaintext)

    def finalizeEncryptor(self):
        return self.encryptor.finalize()

    def updateDecryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)

    def finalizeDecryptor(self):
        return self.decryptor.finalize()

# Auto generate key/IV for encryption
manager = EncryptionManager()

plaintexts = [
    b"SHORT",
    b"MEDIUM MEDIUM MEDIUM",
    b"LONG LONG LONG LONG LONG LONG"
]

ciphertexts = []

for m in plaintexts:
    ciphertexts.append(manager.updateEncryptor(m))
ciphertexts.append(manager.finalizeEncryptor())

for c in ciphertexts:
    print("Recovered", manager.updateDecryptor(c))
print("Recovered", manager.finalizeDecryptor())

# Start Auto Test
manager = EncryptionManager()
ciphertexts = []
recoveredtexts = []
expected = [
    b'SHORT',
    b'MEDIUM MEDIUM MEDIUM',
    b'LONG LONG LONG LONG LONG LONG',
    b'',
    b'',
    ]
    
for m in plaintexts:
    ciphertexts.append(manager.updateEncryptor(m))
ciphertexts.append(manager.finalizeEncryptor())

for c in ciphertexts:
    recoveredtexts.append(manager.updateDecryptor(c))
recoveredtexts.append(manager.finalizeDecryptor())

if expected == recoveredtexts:
    print("[PASS]")
else:
    for r_text, x_text in zip(expected, recoveredtexts):
        if r_text!=x_text:
            print("Mismatch",r_text,x_text)
    print("[FAIL]")
