from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

import sys

issuer_public_key_file, cert_to_check = sys.argv[1:3]
with open(issuer_public_key_file,"rb") as key_reader:
    issuer_public_key = key_reader.read()

issuer_public_key = load_pem_public_key(
    issuer_public_key,
    backend=default_backend())

with open(cert_to_check,"rb") as cert_reader:
    pem_data_to_check = cert_reader.read()
cert_to_check = x509.load_pem_x509_certificate(
    pem_data_to_check, 
    default_backend())
issuer_public_key.verify(
    cert_to_check.signature,
    cert_to_check.tbs_certificate_bytes,
    padding.PKCS1v15(),
    cert_to_check.signature_hash_algorithm)
print("Signature ok! (Exception on failure!)")

# FOR AUTO TESTING:
print("[PASS]") # if we get here, we succeeded