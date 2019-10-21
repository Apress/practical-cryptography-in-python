# NEVER USE THIS. ECB IS _NOT_ SECURE!!!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

test_key = bytes.fromhex('00112233445566778899AABBCCDDEEFF')

aesCipher = Cipher(algorithms.AES(test_key), modes.ECB(), backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

import sys

ifile, ofile = sys.argv[1:3]
with open(ifile, "rb") as reader:
    with open(ofile, "wb+") as writer:
        image_data = reader.read()
        header, body = image_data[:54], image_data[54:]
        body += b"\x00"*(16-(len(body)%16))
        writer.write(header + aesEncryptor.update(body))

# FOR AUTO TEST
if "--auto-test" in sys.argv:
    cmp_file = sys.argv[3]
    with open(ofile,"rb") as test_file_reader:
        with open(cmp_file, "rb") as cmp_file_reader:
            if test_file_reader.read() == cmp_file_reader.read():
                print("[PASS]")
            else:
                print("[FAIL]")