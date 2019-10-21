from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import asyncio, os, sys

PW = b"password"

class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, message, password):
        self.message = message

        # 64 bytes gives us 2 32-byte keys
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64, salt=None, info=None,
            backend=default_backend()
        ).derive(password)
        self._client_write_key = key_material[0:32]
        self._client_read_key = key_material[32:64]

    def connection_made(self, transport):
        plaintext = self.message.encode()
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(self._client_write_key).encrypt(
            nonce, plaintext, b"")
        transport.write(nonce + ciphertext)
        print('Encrypted data sent: {!r}'.format(self.message))

    def data_received(self, data):
        nonce, ciphertext = data[:12], data[12:]
        plaintext = ChaCha20Poly1305(self._client_read_key).decrypt(
            nonce, ciphertext, b"")
        print('Decrypted response from server: {!r}'.format(plaintext.decode()))
        if "--auto-test"in sys.argv:
            if plaintext == message.encode():
                print("[PASS]")
            else:
                print("[FAIL]")

    def connection_lost(self, exc):
        print('The server closed the connection')
        asyncio.get_event_loop().stop()

loop = asyncio.get_event_loop()
message = sys.argv[1]
coro = loop.create_connection(lambda: EchoClientProtocol(message, PW),
                              '127.0.0.1', 8888)
loop.run_until_complete(coro)
loop.run_forever()
loop.close()
