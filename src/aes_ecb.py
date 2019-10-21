# NEVER USE: ECB is not secure!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

key = os.urandom(16)
aesCipher = Cipher(algorithms.AES(key),
                   modes.ECB(),
                   backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

print(aesEncryptor.update(b'0000000000000000'))
print(aesDecryptor.update(b'0000000000000000'))
if(aesCipher.decryptor().update(
    aesCipher.encryptor().update(b'0000000000000000')) ==
        b'0000000000000000'):
    print("[PASS]")
else:
    print("[FAIL]")
