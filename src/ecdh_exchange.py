from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate a private key for use in the exchange.
private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key
# and get a public key from that.
peer_public_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
).public_key()
shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

# AUTO TEST
if len(derived_key) == 32:
    print("[PASS]")
else:
    print("[FAIL]")