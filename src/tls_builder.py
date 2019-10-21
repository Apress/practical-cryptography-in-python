from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import datetime

one_day = datetime.timedelta(1, 0, 0)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())

public_key = private_key.public_key()

certificate = x509.CertificateBuilder(
).subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io')])
).issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io')])
).not_valid_before(datetime.datetime.today() - one_day
).not_valid_after(datetime.datetime.today() + (one_day * 30)
).serial_number(x509.random_serial_number()
).public_key(public_key
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName('cryptography.io')]),
    critical=False,
).add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True,
).sign(
    private_key=private_key, algorithm=hashes.SHA256(),
    backend=default_backend())

# FOR AUTO TESTER #
# this is a no-output test. Just accept
print("[PASS]")
