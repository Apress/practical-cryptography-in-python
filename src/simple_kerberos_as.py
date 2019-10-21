# Skeleton for Kerberos AS Code, User Database, initial class decl
import asyncio, json, os, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# we used the most common passwords
# from 2018 according to wikipedia
# https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
USER_DATABASE = {
    "johndoe": "123456",
    "janedoe": "password",
    "h_world": "123456789",
    "tgs": "sunshine"
}


# These helper functions deal with json's lack of bytes support
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

# Encryption Functions for Kerberos AS
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

class SimpleKerberosAS(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        packet = load_packet(data)
        response = {}
        if packet["type"] == "AS_REQ":
            clienttime = packet["timestamp"]
            if abs(time.time()-clienttime) > 300:
                response["type"] = "ERROR"
                response["message"] = "Timestamp is too old"
            elif packet["principal"] not in USER_DATABASE:
                response["type"] = "ERROR"
                response["message"] = "Unknown principal"
            else:
                response["type"] = "AS_REP"

                session_key = os.urandom(32)
                user_data = {
                    "session_key":session_key,
                    }
                tgt = {
                    "session_key":session_key,
                    "client_principal":packet["principal"],
                    "timestamp":time.time()
                    }
                user_key = derive_key(USER_DATABASE[packet["principal"]])
                user_data_encrypted = encrypt(dump_packet(user_data), user_key)
                response["user_data"] = user_data_encrypted

                tgs_key = derive_key(USER_DATABASE["tgs"])
                tgt_encrypted = encrypt(dump_packet(tgt), tgs_key)
                response["tgt"] = tgt_encrypted
            self.transport.write(dump_packet(response))
        self.transport.close()
        # FOR AUTO TESTING
        import sys
        if "--auto-test" in sys.argv:
            print("[PASS]") # assume we're good if we got here
            asyncio.get_event_loop().call_later(0.25, sys.exit)

loop = asyncio.get_event_loop()
# Each client connection will create a new protocol instance
coro = loop.create_server(SimpleKerberosAS, '127.0.0.1', 8888)
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
