from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import gmpy2

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)
    
private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
  )
public_key = private_key.public_key()

message = b'test'

###
# WARNING: PKCS #1 v1.5 is obsolete and has vulnerabilities
# DO NOT USE EXCEPT WITH LEGACY PROTOCOLS
ciphertext = public_key.encrypt(
    message,
    padding.PKCS1v15()
)

ciphertext_as_int = bytes_to_int(ciphertext)
recovered_as_int = simple_rsa_decrypt(ciphertext_as_int, private_key)
recovered = int_to_bytes(recovered_as_int)

print("Plaintext: {}".format(message))
print("Recovered: {}".format(recovered))

if recovered != message and recovered.endswith(message):
    print("[PASS]")
else:
    print("[FAIL]")
