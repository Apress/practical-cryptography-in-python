from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class ECDHExchange:
    def __init__(self, curve):
        self._curve = curve

        # Generate an ephemeral private key for use in the exchange.
        self._private_key = ec.generate_private_key(
            curve, default_backend())

        self.enc_key = None
        self.mac_key = None

    def get_public_bytes(self):
        public_key = self._private_key.public_key()
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return raw_bytes

    def generate_session_key(self, peer_bytes):
        peer_public_key = serialization.load_pem_public_key(
            peer_bytes,
            backend=default_backend())
        shared_key = self._private_key.exchange(
            ec.ECDH(),
            peer_public_key)

        # derive 64 bytes of key material for 2 32-byte keys
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=None,
            backend=default_backend()).derive(shared_key)

        # get the encryption key
        self.enc_key = key_material[:32]

        # derive an MAC key
        self.mac_key = key_material[32:64]

# FOR AUTO TEST
client_x = ECDHExchange(ec.SECP384R1())
client_y = ECDHExchange(ec.SECP384R1())
client_x.generate_session_key(client_y.get_public_bytes())
client_y.generate_session_key(client_x.get_public_bytes())
if client_x.enc_key and client_x.mac_key and client_x.enc_key == client_y.enc_key and client_x.mac_key == client_y.mac_key:
    print("[PASS]")
else:
    print("[FAIL]")
