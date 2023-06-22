# Errata for *Practical Cryptography in Python*

On **page 42** [Incorrect source code]:
 
The source code that starts at the bottom of page 42 is (incorrectly) a duplicate of *Listing 2-6* at the top of page 39. It should read:

    >> import os, base64
    >> salt = os.urandom(16) # 16-byte, random salt
    >> base64.b64encode(salt)
    b'Xgdue/5H8qZk/r8YT3Nx1A=='

***
On **page 96** [Minor Mistake]:
 
In the section "Exploiting Malleability", the 3rd paragraph reads: 

"Cipher block chaining mode is different because a change to a single byte of ciphertext will affect 
all subsequent blocks."

But that is incorrect. Changing a single byte of ciphertext will affect only the block where the changed byte 
belongs and the next block. No other block in the affected. 

Changing a single byte of a ciphertext that was encrypted
with AES-CBC has the potential to change at most $17$ bytes of the plaintext.

Let's see why this is. Suppose the byte that was changed belongs to $C_i$. Then the receiving side will perform
$P_i = D(K, C_i) \oplus C_{i-1}$. Thus, all $16$ bytes of $P_i$ have the potential to change due to the avalanche
property of the decryption function of AES. Then $P_{i+1} = D(K, C_{i+1}) \oplus C_i$. Thus $P_{i+1}$ will also 
be affected. But only a single byte of $P_{i+1}$ will be affected. All other plaintexts will not be affected.

***
On **pages 135-137** [Clarification]:

In the section on the RSA Common Modulus Attack, it fails to mention that the GCD (Greatest Common Divisor) of the public exponents (e values) must be 1. In practice, this is not a problem because the GCD of two prime numbers is 1 and RSA public exponents are usually prime. While not required, picking a prime number for the public exponent is the easiest way of ensuring that the requirements are met. 

However, for completeness, the following check should be inserted into Listing 4-6 after line 20.

    if gcd != 1:
        raise ValueError("Common modulus attack requires GCD(e1,e2)==1")
        
****
On **page 201** [Typo]

The sentence "It is the subject's private key that is being stored in the certificate" should read, "It is the subject's public key that is being stored in the certificate."

****
On **page 215** [typo]

The source code at approximately line 42 reads, `ciphertext = data+signature`. It should read `ciphertext += signature`. The corresponding source code in github has also been updated.
