# Errata for *Practical Cryptography in Python*

On **page 42** [Incorrect source code]:
 
The source code that starts at the bottom of page 42 is (incorrectly) a duplicate of *Listing 2-6* at the top of page 39. It should read:

    >> import os, base64
    >> salt = os.urandom(16) # 16-byte, random salt
    >> base64.b64encode(salt)
    b'Xgdue/5H8qZk/r8YT3Nx1A=='

***

