# ACME generates a purchase message in their storefront.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# WARNING! Never do this. Resuing a key/IV is irresponsible!
preshared_key = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
preshared_iv  = bytes.fromhex('00000000000000000000000000000000')

purchase_message = b"""
<XML>
  <CreditCardPurchase>
    <Merchant>Acme Inc</Merchant>
    <Buyer>John Smith</Buyer>
    <Date>01/01/2001</Date>
    <Amount>$100.00</Amount>
    <CCNumber>555-555-555-555</CCNumber
  </CreditCardPurchase>
</XML>
"""

aesContext = Cipher(algorithms.AES(preshared_key),
                    modes.CTR(preshared_iv),
                    backend=default_backend())
encryptor = aesContext.encryptor()
encrypted_message = encryptor.update(purchase_message)

strip_header = b"""
<XML>
  <CreditCardPurchase>
    <Merchant>Acme Inc</Merchant>
"""

bad_message_header = b"""
<XML>
  <CreditCardPurchase>
    <Merchant>EVIL LLC</Merchant>
"""
keystream = bytes([encrypted_message[i]^strip_header[i] for i in range(len(strip_header))])
bad_encrypted_header = bytes([keystream[i]^bad_message_header[i] for i in range(len(keystream))])
bad_encrypted_message = bad_encrypted_header + encrypted_message[len(bad_encrypted_header):]
bad_decrypted_message = aesContext.decryptor().update(bad_encrypted_message)

bad_message = b"""
<XML>
  <CreditCardPurchase>
    <Merchant>EVIL LLC</Merchant>
    <Buyer>John Smith</Buyer>
    <Date>01/01/2001</Date>
    <Amount>$100.00</Amount>
    <CCNumber>555-555-555-555</CCNumber
  </CreditCardPurchase>
</XML>
"""
print(bad_decrypted_message.decode())
if bad_message == bad_decrypted_message:
    print("[PASS]")
else:
    print("[FAIL]")