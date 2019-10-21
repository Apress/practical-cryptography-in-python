from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, sys, struct

READ_SIZE = 4096

def encrypt_file(plainpath, cipherpath, password):    
    # Derive key with a random 16-byte salt
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32,
                n=2**14, r=8, p=1,
                backend=default_backend())
    key = kdf.derive(password)

    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()).encryptor()
    
    associated_data = iv + salt

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)
    
    with open(cipherpath, "wb+") as fcipher:
        # Make space for the header (12 + 16 + 16), overwritten last
        fcipher.write(b"\x00"*(12+16+16))
        
        # Encrypt and write the main body
        with open(plainpath, "rb") as fplain:
            for plaintext in iter(lambda: fplain.read(READ_SIZE), b''):
                ciphertext = encryptor.update(plaintext)
                fcipher.write(ciphertext)
            ciphertext = encryptor.finalize()   # Always b''.
            fcipher.write(ciphertext) # For clarity
            
        header = associated_data + encryptor.tag
        fcipher.seek(0,0)
        fcipher.write(header)
            
def decrypt_file(cipherpath, plainpath, password):
    with open(cipherpath, "rb") as fcipher:
        # read the IV (12 bytes) and the salt (16 bytes)
        associated_data = fcipher.read(12+16)
        
        iv = associated_data[0:12]
        salt = associated_data[12:28]
        
        # derive the same key from the password + salt
        kdf = Scrypt(salt=salt, length=32,
                n=2**14, r=8, p=1,
                backend=default_backend())
        key = kdf.derive(password)
        
        # get the tag. GCM tags are always 16 bytes
        tag = fcipher.read(16)
        
        # Construct an AES-GCM Cipher object with the given key and IV
        # For decryption, the tag is passed in as a parameter
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        
        with open(plainpath, "wb+") as fplain:
            for ciphertext in iter(lambda: fcipher.read(READ_SIZE),b''):
                plaintext = decryptor.update(ciphertext)
                fplain.write(plaintext)
        
if __name__=="__main__":
    if len(sys.argv) == 1: # auto test
        orig_file, enc_file, pw = "test_data_file.txt", "test_data_file_txt.locked", b"password"
        orig_contents = "This is a test\nOf a two line file."
        with open(orig_file,"w+") as f:
            f.write(orig_contents)
        encrypt_file(orig_file, enc_file, pw)
        
        recover_file = "test_data_file_recovered.txt"
        decrypt_file(enc_file, recover_file, pw)
        
        with open(recover_file) as f:
            recover_contents = f.read()
        if orig_contents == recover_contents:
            print("[PASS]")
        else:
            print("[FAIL]")
    elif sys.argv[1] == "encrypt":
        ifile, ofile, pw = sys.argv[2:]
        encrypt_file(ifile, ofile, pw.encode())
    elif sys.argv[1] == "decrypt":
        ifile, ofile, pw = sys.argv[2:]
        decrypt_file(ifile, ofile, pw.encode())