# Errata for *Practical Cryptography in Python*

On **page 42** [Incorrect source code]:
 
The source code that starts at the bottom of page 42 is (incorrectly) a duplicate of *Listing 2-6* at the top of page 39. It should read:

    >> import os, base64
    >> salt = os.urandom(16) # 16-byte, random salt
    >> base64.b64encode(salt)
    b'Xgdue/5H8qZk/r8YT3Nx1A=='

***
On **pages 135-137** [Clarification]:

In the section on the RSA Common Modulus Attack, it fails to mention that the GCD (Greatest Common Divisor) of the public exponents (e values) must be 1. In practice, this is not a problem because the GCD of two prime numbers is 1 and RSA public exponents are usually prime. While not required, picking a prime number for the public exponent is the easiest way of ensuring that the requirements are met. 

However, for completeness, the following check should be inserted into Listing 4-6 after line 20.

    if gcd != 1:
        raise ValueError("Common modulus attack requires GCD(e1,e2)==1")
        
****

