# Reasonably secure concept. Still, NEVER use it for production code.
# Use a crypto library instead!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def CBCMAC(message, key):
    aesCipher = Cipher(algorithms.AES(key),
                       modes.CBC(bytes(16)), # 16 zero bytes
                       backend=default_backend())
    aesEncryptor = aesCipher.encryptor()
    padder = padding.PKCS7(128).padder()

    padded_message = padder.update(message)
    padded_message_with_length = len(message).to_bytes(4, "big") + padded_message
    ciphertext = aesEncryptor.update(padded_message_with_length)
    return ciphertext[-16:]


def BROKEN_CBCMAC1(message, key, pad=True):
    aesCipher = Cipher(algorithms.AES(key),
                       modes.CBC(bytes(16)), # 16 zero bytes
                       backend=default_backend())
    aesEncryptor = aesCipher.encryptor()
    
    if pad:
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message)+padder.finalize()
    elif len(message) % 16 == 0:
        padded_message = message
    else:
        raise Exception("Unpadded input not a multiple of 16!")
    ciphertext = aesEncryptor.update(padded_message)
    return ciphertext[-16:] # the last 16 bytes are the last block

# Begin automated test
def prependAttack(original, prependMessage, key):
    # assumes prependMessage is multiple of 16
    # assumes original is at least 16
    prependMac = BROKEN_CBCMAC1(prependMessage, key, pad=False)
    newFirstBlock = bytearray(original[:16])
    for i in range(16):
        newFirstBlock[i] ^= prependMac[i]
    newFirstBlock = bytes(newFirstBlock)
    return prependMessage + newFirstBlock + original[16:]
    
key = os.urandom(32)
originalMessage = b"attack the enemy forces at dawn!"
prependMessage = b"do not attack. (End of message, padding follows)"
newMessage = prependAttack(originalMessage, prependMessage, key)
mac1 = CBCMAC(originalMessage, key)
mac2 = BROKEN_CBCMAC1(newMessage, key)
if mac1 != mac2:
    print("[PASS]")
else:
    print("[FAIL]")