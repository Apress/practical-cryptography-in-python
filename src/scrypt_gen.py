import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

salt = os.urandom(16)

kdf = Scrypt(salt=salt, length=32,
                n=2**14, r=8, p=1,
                backend=default_backend())

key = kdf.derive(b"my great password")
print("KDF output:", key.hex())

kdf = Scrypt(salt=salt, length=32,
             n=2**14, r=8, p=1,
             backend=default_backend())
kdf.verify(b"my great password", key)
print("Success! (Exception if mismatch)")

# If we got here, we passed
print("[PASS]")
