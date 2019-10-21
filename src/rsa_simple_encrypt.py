#!/usr/bin/python
# FOR TRAINING USE ONLY! DO NOT USE THIS FOR REAL CRYPTOGRAPHY

import gmpy2, sys, binascii, string, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

#### DANGER ####
# The following RSA encryption and decryption is
# completely unsafe and terribly broken. DO NOT USE
# for anything other than the practice exercise
################
def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
)
public_key = private_key.public_key()

n = public_key.public_numbers().n
a = 5
b = 10

encrypted_a = simple_rsa_encrypt(a, public_key)
encrypted_b = simple_rsa_encrypt(b, public_key)

encrypted_product = (encrypted_a * encrypted_b) % n

product = simple_rsa_decrypt(encrypted_product, private_key)
print("{} x {} = {}".format(a,b, product))

if product == a*b:
    print("[PASS]")
else:
    print("[FAIL]")
