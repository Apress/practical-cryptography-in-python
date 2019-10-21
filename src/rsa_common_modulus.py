#!/usr/bin/python3.4
import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Derived From: https://github.com/a0xnirudh/Exploits-and-Scripts/tree/master/RSA Attacks
def common_modulus_decrypt(c1, c2, key1, key2):
    key1_numbers = key1.public_numbers()
    key2_numbers = key2.public_numbers()
    
    if key1_numbers.n != key2_numbers.n:
        raise ValueError("Common modulus attack requires a common modulus")
    n = key1_numbers.n
    
    if key1_numbers.e == key2_numbers.e:
        raise ValueError("Common modulus attack requires different public exponents")
    
    e1, e2 = key1_numbers.e, key2_numbers.e
    num1, num2 = min(e1, e2), max(e1, e2)
    
    while num2 != 0:
        num1, num2 = num2, num1 % num2
    gcd = num1
    
    a = gmpy2.invert(key1_numbers.e, key2_numbers.e)
    b = float(gcd - (a*e1))/float(e2)

    i = gmpy2.invert(c2, n)
    mx = pow(c1, a, n)
    my = pow(i, int(-b), n)
    return mx * my % n
       
def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    c = gmpy2.powmod(m, numbers.e, numbers.n)
    return c

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    m = gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)
    return m
    
def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')
    
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def main():
    print("Testing common modulus attack.")
    print("Generating private key.")

    private_key1 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key1 = private_key1.public_key()
    # For testing, replace "input()" with a hardcoded result
    input = lambda *args: "test_message"
    message = input("\nMessage to Encrypt: ").encode()
    message_as_int = bytes_to_int(message)
    print("message as int:", message_as_int)
    
    print("\nEncrypting under first public key")
    print("N={}".format(public_key1.public_numbers().n))
    print("e={}".format(public_key1.public_numbers().e))
    
    ciphertext1 = simple_rsa_encrypt(message_as_int, public_key1)
    print("ciphertext as integer:",ciphertext1)
    
    
    print("\nEncrypting key under second public key. Picking e=3 arbitrarily.")
    n = public_key1.public_numbers().n
    public_key2  = rsa.RSAPublicNumbers(3, n).public_key(default_backend())
    print("N={}".format(public_key2.public_numbers().n))
    print("e={}".format(public_key2.public_numbers().e))
    
    ciphertext2 = simple_rsa_encrypt(message_as_int, public_key2)
    print("ciphertext as integer:",ciphertext2)
    
    print("Recovering message:")
    recovered_as_int = common_modulus_decrypt(ciphertext1, ciphertext2, public_key1, public_key2)
    
    print("recovered int", recovered_as_int)
    recovered = int_to_bytes(recovered_as_int)
    print("\nrecovered message: ", recovered)
    if recovered == message:
        print("[PASS]")
    else:
        print("[FAIL]")

if __name__ == '__main__':
    main()
