def sslv3Pad(msg):
    padNeeded = (16 - (len(msg) % 16)) - 1
    padding = padNeeded.to_bytes(padNeeded+1, "big")
    return msg+padding

def sslv3Unpad(padded_msg):
    paddingLen = padded_msg[-1] + 1
    return padded_msg[:-paddingLen]

test_message = b"A"
pad_message = sslv3Pad(test_message)
unpad_message = sslv3Unpad(pad_message)

if len(pad_message) % 16 == 0 and test_message == unpad_message:
    print("[PASS]")
else:
    print("[FAIL]")