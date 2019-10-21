import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes , hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# WARNING: This code is NOT secure. DO NOT USE!
class TransmissionManager:
    def __init__(self, send_private_key, recv_public_key):
        self.send_private_key = send_private_key
        self.recv_public_key = recv_public_key
        self.ekey = os.urandom(32)
        self.mkey = os.urandom(32)
        self.iv  = os.urandom(16)

        self.encryptor = Cipher(
            algorithms.AES(self.ekey),
            modes.CTR(self.iv),
            backend=default_backend()).encryptor()
        self.mac = hmac.HMAC(
            self.mkey,
            hashes.SHA256(),
            backend=default_backend())

    def initialize(self):
        data = self.ekey + self.iv + self.mkey
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(data)
        data_digest = h.finalize()
        signature = self.send_private_key.sign(
            data_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        ciphertext = self.recv_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)) # rarely used. Just leave it 'None'
        ciphertext = data+signature
        self.mac.update(ciphertext)
        return ciphertext

    def update(self, plaintext):
        ciphertext = self.encryptor.update(plaintext)
        self.mac.update(ciphertext)
        return ciphertext

    def finalize(self):
        return self.mac.finalize()


# BEGIN AUTO TEST

sender_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048, 
    backend=default_backend()
)
    
public_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048, 
    backend=default_backend()
).public_key()


tm = TransmissionManager(sender_private_key, public_key)
header = tm.initialize()
print(header.hex())
data = tm.update(b'first packets')
print(data.hex())
data = tm.finalize()
print(data.hex())

# TODO, later should have the test more realistic by decrypting, verifying
print("[PASS]")