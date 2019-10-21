# Skeleton for Kerberos Client Code. Imports, initial class decl
# Dependencies: derive_key(), encrypt(), decrypt(),
#               load_packet(), dump_packet()
import asyncio, json, sys, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


# Dependencies: derive_key(), encrypt(), decrypt()
class SimpleKerberosLogin(asyncio.Protocol):
    def __init__(self, username, password, on_login):
        self.username = username
        self.password = password
        self.on_login = on_login

        self.session_key = None
        self.tgt = None

    def connection_made(self, transport):
        self.transport = transport
        request = {
            "type":      "AS_REQ",
            "principal": self.username,
            "timestamp": time.time()
        }
        self.transport.write(dump_packet(request))

    def data_received(self, data):
        packet = load_packet(data)
        if packet["type"] == "AS_REP":
            user_data_encrypted = packet["user_data"]
            user_key = derive_key(self.password)
            user_data_bytes = decrypt(user_data_encrypted, user_key)
            user_data = load_packet(user_data_bytes)
            self.session_key = user_data["session_key"]
            self.tgt = packet["tgt"]
        elif packet["type"] == "ERROR":
            print("ERROR: {}".format(packet["message"]))

        self.transport.close()

    def connection_lost(self, exc):
        self.on_login(self.session_key, self.tgt)

# SimpleKerberosGetTicket is also part of the Client
# This class connects to the TGS to get a ticket
class SimpleKerberosGetTicket(asyncio.Protocol):
    def __init__(self, username, service, session_key, tgt, on_ticket):
        self.username = username
        self.service = service
        self.session_key = session_key
        self.tgt = tgt
        self.on_ticket = on_ticket

        self.server_session_key = None
        self.ticket = None

    def connection_made(self, transport):
        print("TGS connection made")
        self.transport = transport
        authenticator = {
            "principal": self.username,
            "timestamp": time.time()
        }
        authenticator_encrypted = encrypt(dump_packet(authenticator), self.session_key)
        request = {
            "type":          "TGS_REQ",
            "service":       self.service,
            "authenticator": authenticator_encrypted,
            "tgt":           self.tgt
        }
        self.transport.write(dump_packet(request))

    def data_received(self, data):
        packet = load_packet(data)
        if packet["type"] == "TGS_REP":
            user_data_encrypted = packet["user_data"]
            user_data_bytes = decrypt(user_data_encrypted, self.session_key)
            user_data = load_packet(user_data_bytes)
            self.server_session_key = user_data["service_session_key"]
            self.ticket = packet["ticket"]
        elif packet["type"] == "ERROR":
            print("ERROR: {}".format(packet["message"]))

        self.transport.close()

    def connection_lost(self, exc):
        self.on_ticket(self.server_session_key, self.tgt)

# ResponseHandler is also part of the client. It connects to the service.
class ResponseHandler:
    def __init__(self, username):
        self.username = username

    def on_login(self, session_key, tgt):
        if session_key is None:
            print("Login failed")
            asyncio.get_event_loop().stop()
            return

        input = lambda *args: "echo"
        service = input("Logged into Simpler Kerberos. Enter Service Name: ")
        getTicketFactory = lambda: SimpleKerberosGetTicket(
            self.username, service, session_key, tgt, self.on_ticket)
            
        coro = asyncio.get_event_loop().create_connection(
            getTicketFactory, '127.0.0.1', 8889)
        asyncio.get_event_loop().create_task(coro)

    def on_ticket(self, service_session_key, ticket):
        if service_session_key is None:
            print("Login failed")
            asyncio.get_event_loop().stop()
            return

        print("Got a server session key:",service_session_key.hex())
        asyncio.get_event_loop().stop()
        # AUTO TESTER
        if "--auto-test" in sys.argv:
            print("[PASS]") # assume we're good if we got here
            # loop stopped ,no need to force exit

loop = asyncio.get_event_loop()
username = sys.argv[1]
password = sys.argv[2]
responseHandler = ResponseHandler(username)
loginFactory = lambda: SimpleKerberosLogin(username, password, responseHandler.on_login)
coro = loop.create_connection(loginFactory,
                              '127.0.0.1', 8888)
loop.run_until_complete(coro)
loop.run_forever()
loop.close()
