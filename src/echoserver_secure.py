import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import asyncio, os

PW = b"password"

class EchoServerProtocol(asyncio.Protocol):
    def __init__(self, password):
        # 64 bytes gives us 2 32-byte keys.
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64, salt=None, info=None,
            backend=default_backend()
        ).derive(password)
        self._server_read_key = key_material[0:32]
        self._server_write_key = key_material[32:64]

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        # Split out the nonce and the ciphertext.
        nonce, ciphertext = data[:12], data[12:]
        plaintext = ChaCha20Poly1305(self._server_read_key).decrypt(
            nonce, ciphertext, b"")
        message = plaintext.decode()
        print('Decrypted message from client: {!r}'.format(message))

        print('Echo back message: {!r}'.format(message))
        reply_nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(self._server_write_key).encrypt(
            reply_nonce, plaintext, b"")
        self.transport.write(reply_nonce + ciphertext)

        print('Close the client socket')
        self.transport.close()
        # FOR AUTO TESTING. Shutdown after echo
        if "--auto-test" in sys.argv:
            print("[PASS]")
            asyncio.get_event_loop().call_later(0.25,sys.exit)

loop = asyncio.get_event_loop()
# Each client connection will create a new protocol instance
coro = loop.create_server(lambda: EchoServerProtocol(PW), '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()

