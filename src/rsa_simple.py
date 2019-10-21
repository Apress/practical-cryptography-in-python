#!/usr/bin/python3
# FOR TRAINING USE ONLY! DO NOT USE THIS FOR REAL CRYPTOGRAPHY

import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#### DANGER ####
# The following RSA encryption and decryption is
# completely unsafe and terribly broken. DO NOT USE
# for anything other than the practice exercise
################
def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)
#### DANGER ####

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def main():
# TESTING APPARATUS FOR AUTO TESTING OF UI
    storage = {}
    test_message = "TEST MESSAGE"
    inputs = ['5','test_private_key.pem','test_public_key.pem','1',test_message,'2','REPLACE_ME_cipher1','6']
    def batch_input(m):
        fake_input = inputs.pop(0)
        if fake_input.startswith("REPLACE_ME_"):
            key = fake_input.replace("REPLACE_ME_","")
            return storage[key]
        return fake_input
    input = batch_input
    
    class Tracker:
        pass
    tracker = Tracker
    tracker.encode_count = 0
    tracker.decode_count = 0

    def track_cipher(c):
        tracker.encode_count += 1
        storage["cipher{}".format(tracker.encode_count)] = c
        return c

    def track_recover(p):
        tracker.decode_count += 1
        storage["recover{}".format(tracker.decode_count)] = p
        return p
    public_key_file = None
    private_key_file = None
    public_key = None
    private_key = None
    while True:
        print("Simple RSA Crypto")
        print("--------------------")
        print("\tprviate key file: {}".format(private_key_file))
        print("\tpublic key file: {}".format(public_key_file))
        print("\t1. Encrypt Message.")
        print("\t2. Decrypt Message.")
        print("\t3. Load public key file.")
        print("\t4. Load private key file.")
        print("\t5. Create and load new public and private key files.")
        print("\t6. Quit.\n")
        choice = input(">> ")
        if choice == '1':
            if not public_key:
                print("\nNo public key loaded\n")
            else:
                message = input("\nPlaintext: ").encode()
                message_as_int = bytes_to_int(message)
                cipher_as_int = simple_rsa_encrypt(message_as_int, public_key)
                cipher = int_to_bytes(cipher_as_int)
                track_cipher(binascii.hexlify(cipher).decode())
                print(storage)
                print("\nCiphertext (hexlified): {}\n".format(binascii.hexlify(cipher)))
        elif choice == '2':
            if not private_key:
                print("\nNo private key loaded\n")
            else:
                cipher_hex = input("\nCiphertext (hexlified): ").encode()
                cipher = binascii.unhexlify(cipher_hex)
                cipher_as_int = bytes_to_int(cipher)
                message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
                message = int_to_bytes(message_as_int)
                track_recover(message.decode())
                print("\nPlaintext: {}\n".format(message))
        elif choice == '3':
            public_key_file_temp = input("\nEnter public key file: ")
            if not os.path.exists(public_key_file_temp):
                print("File {} does not exist.")
            else:
                with open(public_key_file_temp, "rb") as public_key_file_object:
                    public_key = serialization.load_pem_public_key(
                                     public_key_file_object.read(),
                                     backend=default_backend())
                    public_key_file = public_key_file_temp
                    print("\nPublic Key file loaded.\n")

                    # unload private key if any
                    private_key_file = None
                    private_key = None
        elif choice == '4':
            private_key_file_temp = input("\nEnter private key file: ")
            if not os.path.exists(private_key_file_temp):
                print("File {} does not exist.")
            else:
                with open(private_key_file_temp, "rb") as private_key_file_object:
                    private_key = serialization.load_pem_private_key(
                                     private_key_file_object.read(),
                                     backend=default_backend(),
                                     password=None)
                    private_key_file = private_key_file_temp
                    print("\nPrivate Key file loaded.\n")

                    # load public key for private key
                    # (unload previous public key if any)
                    public_key = private_key.public_key()
                    public_key_file = None
        elif choice == '5':
            private_key_file_temp = input("\nEnter a file name for new private key: ")
            public_key_file_temp  = input("\nEnter a file name for a new public key: ")
            if os.path.exists(private_key_file_temp) or os.path.exists(public_key_file_temp):
                print("File already exists.")
            else:
                with open(private_key_file_temp, "wb+") as private_key_file_obj:
                    with open(public_key_file_temp, "wb+") as public_key_file_obj:

                        private_key = rsa.generate_private_key(
                                          public_exponent=65537,
                                          key_size=2048,
                                          backend=default_backend()
                                      )
                        public_key = private_key.public_key()

                        private_key_bytes = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                        private_key_file_obj.write(private_key_bytes)
                        public_key_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        public_key_file_obj.write(public_key_bytes)

                        public_key_file = None
                        private_key_file = private_key_file_temp
        elif choice == '6':
            print("\n\nTerminaing. This program will self destruct in 5 seconds.\n")
            break
        else:
            print("\n\nUnknown option {}.\n".format(choice))
    if storage["recover1"] != test_message:
        print("[FAIL]")
    else:
        print("[PASS]")

if __name__ == '__main__':
    main()
