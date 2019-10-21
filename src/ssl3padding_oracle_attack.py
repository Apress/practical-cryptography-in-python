from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Oracle:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def accept(self, ciphertext):
        aesCipher = Cipher(algorithms.AES(self.key),
                           modes.CBC(self.iv),
                           backend=default_backend())
        decryptor = aesCipher.decryptor()
        plaintext = decryptor.update(ciphertext)
        plaintext += decryptor.finalize()
        return plaintext[-1] == 15

# This function assumes that the last cipher text block is a full
# block of SSLV3 padding
def lucky_get_one_byte(iv, ciphertext, block_number, oracle):
    block_start = block_number * 16
    block_end = block_start + 16
    block = ciphertext[block_start:block_end]

    # Copy the block over the last block.
    mod_ciphertext = ciphertext[:-16] + block
    if not oracle.accept(mod_ciphertext):
        return False, None

    # This is valid! Let's get the byte!
    # We first need the byte decrypted from the block.
    # It was XORed with second to last block, so
    # byte = 15 XOR (last byte of second-to-last block).
    second_to_last = ciphertext[-32:-16]
    intermediate = second_to_last[-1]^15

    # We still have to XOR it with its *real*
    # preceding block in order to get the true value.
    if block_number == 0:
        prev_block = iv
    else:
        prev_block = ciphertext[block_start-16:block_start]

    return True, intermediate ^ prev_block[-1]

original_message = b"this is the original message with a whole bunch of data designed to be an even number of blocks."
fixed_padding = b"000000000000000\x15"
recovered_message = b""

total_tries = 0
one_byte_tries = 0
index = 0
while recovered_message != original_message:
    key = os.urandom(16)
    iv = os.urandom(16)
    # create modified original_message to get byte to decode in right place"
    adjustment = 15-(index%16)
    prefix = b"0"*adjustment
    if adjustment:
        padded_message = prefix + original_message[:-adjustment] + fixed_padding
    else:  
        padded_message = original_message + fixed_padding
    aesContext = Cipher(algorithms.AES(key),
                            modes.CBC(iv),
                            backend=default_backend())
    encryptor = aesContext.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    oracle = Oracle(key, iv)
    one_byte_tries += 1
    success, byte = lucky_get_one_byte(iv, ciphertext, int(index/16), oracle)
    if success:
        recovered_message += byte.to_bytes(length=1,byteorder="big")
        index += 1
        total_tries += one_byte_tries
        print("Found one byte: {}. Took {} tries. Advancing to index {}".format(byte, one_byte_tries, index))
        one_byte_tries = 0
        #break
        print("Recovered currently {}".format(recovered_message))
print("Recovered message in {} tries.".format(total_tries))
print("Total bytes recovered: {}".format(len(recovered_message)))
print("Average tries per byte: {}".format(total_tries/len(recovered_message)))

if recovered_message and recovered_message == original_message:
    print('[PASS]')
else:
    print('[FAIL]')
		