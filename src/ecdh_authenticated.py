from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import struct # needed for get_signed_public_pytes

class AuthenticatedECDHExchange:
    def __init__(self, curve, auth_private_key):
        self._curve = curve
        self._private_key = ec.generate_private_key(
            self._curve,
            default_backend())
        self.enc_key = None
        self.mac_key = None

        self._auth_private_key = auth_private_key
        
    # Part of AuthenticatedECDHExchange class
    def get_signed_public_bytes(self):
        public_key = self._private_key.public_key()

        # Here are the raw bytes.
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # This is a signature to prove who we are.
        signature = self._auth_private_key.sign(
            raw_bytes,
            ec.ECDSA(hashes.SHA256()))

        # Signature size is not fixed. Include a length field first.
        return struct.pack("I", len(signature)) + raw_bytes + signature

    def generate_session_key(self, peer_bytes, signature_pub_key):
        peer_key_signature_len, = struct.unpack("I", peer_bytes[:4])
        public_key_bytes        = peer_bytes[4:-peer_key_signature_len]
        public_key_signature    = peer_bytes[-peer_key_signature_len: ]
        
        signature_pub_key.verify(
            public_key_signature,
            public_key_bytes,
            ec.ECDSA(hashes.SHA256()))
        
        peer_public_key = serialization.load_pem_public_key(
            public_key_bytes,
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
private_key_x = ec.generate_private_key(ec.SECP384R1(), default_backend())
private_key_y = ec.generate_private_key(ec.SECP384R1(), default_backend())
client_x = AuthenticatedECDHExchange(ec.SECP384R1(), private_key_x)
client_y = AuthenticatedECDHExchange(ec.SECP384R1(), private_key_y)
client_x.generate_session_key(client_y.get_signed_public_bytes(), private_key_y.public_key())
client_y.generate_session_key(client_x.get_signed_public_bytes(), private_key_x.public_key())

if client_x.enc_key and client_x.mac_key and client_x.enc_key == client_y.enc_key and client_x.mac_key == client_y.mac_key:
    print("[PASS]")
else:
    print("[FAIL]")
