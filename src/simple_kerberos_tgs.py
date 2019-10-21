# Skeleton for Kerberos TGS. Imports, initial class decl, Service DB
# Dependencies: derive_key(), encrypt(), decrypt(),
#               load_packet(), dump_packet()
import asyncio, json, os, time, sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# we used the most common passwords
# from 2018 according to wikipedia
# https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
SERVICE_DATABASE = {
    "echo":"qwerty",
}

def dump_packet(p):
    for k, v in p.items():
        if isinstance(v, bytes):
            p[k] = list(v)
    return json.dumps(p).encode('utf-8')

def load_packet(json_data):
    p = json.loads(json_data)
    for k, v in p.items():
        if isinstance(v, list):
            p[k] = bytes(v)
    return p

def derive_key(password):
    return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(password.encode())

def encrypt(data, key):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(b"\x00"*16),
        backend=default_backend()
    ).encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(data) + padder.finalize()
    return encryptor.update(padded_message) + encryptor.finalize()

def decrypt(encrypted_data, key):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(b"\x00"*16),
        backend=default_backend()
    ).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpadder.update(padded_message) + unpadder.finalize()

class SimpleKerberosTGS(asyncio.Protocol):
    def __init__(self, password):
        self.password = password

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        packet = load_packet(data)
        response = {}
        if packet["type"] == "TGS_REQ":
            tgsKey = derive_key(self.password)
            tgt_bytes = decrypt(packet["tgt"], tgsKey)
            tgt = load_packet(tgt_bytes)

            authenticator_bytes = decrypt(packet["authenticator"], tgt["session_key"])
            authenticator = load_packet(authenticator_bytes)

            clienttime = authenticator["timestamp"]
            if abs(time.time()-clienttime) > 300:
                response["type"] = "ERROR"
                response["message"] = "Timestamp is too old"
            elif authenticator["principal"] != tgt["client_principal"]:
                response["type"] = "ERROR"
                response["message"] = "Principal mismatch"
            elif packet["service"] not in SERVICE_DATABASE:
                response["type"] = "ERROR"
                response["message"] = "Unknown service"
            else:
                response["type"] = "TGS_REP"

                service_session_key = os.urandom(32)
                user_data = {
                    "service":             packet["service"],
                    "service_session_key": service_session_key,
                    }
                ticket = {
                    "service_session_key": service_session_key,
                    "client_principal":    authenticator["principal"],
                    "timestamp":           time.time()
                    }
                user_data_encrypted = encrypt(dump_packet(user_data), tgt["session_key"])
                response["user_data"] = user_data_encrypted

                service_key = derive_key(SERVICE_DATABASE[packet["service"]])
                ticket_encrypted = encrypt(dump_packet(ticket), service_key)
                response["ticket"] = ticket_encrypted
            self.transport.write(dump_packet(response))
        self.transport.close()
        # FOR AUTO TESTING
        if "--auto-test" in sys.argv:
            print("[PASS]") # assume we're good if we got here
            asyncio.get_event_loop().call_later(0.25, sys.exit)

loop = asyncio.get_event_loop()
password = sys.argv[1]
# Each client connection will create a new protocol instance
coro = loop.create_server(lambda: SimpleKerberosTGS(password), '127.0.0.1', 8889)
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
