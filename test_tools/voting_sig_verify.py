from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import struct


k = input("Input pubkey: ")
k = bytes.fromhex(k)
assert len(k) == 65
n = input("Input nonce: ")
n = bytes.fromhex(n)
sig = input("Input sig: ")
sig = bytes.fromhex(sig)

h = SHA256.new()
h.update(n)
h.update(b'\x00'*32) # start_time
h.update(b'\x00'*32) # end_time
h.update(struct.pack("<I", 4)) # num_options
h.update(struct.pack("<I", 2)) # num_voters

h.update(k) # voter0 key
h.update(struct.pack("<I", 3)) # voter0 weight
h.update(k) # voter1 key
h.update(struct.pack("<I", 4)) # voter1 weight

h.update(struct.pack("<Q", 4)) # description_size
h.update(b'abcd') # description

der_key = b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
der_key += k

key = ECC.import_key(der_key)
vr = DSS.new(key, 'fips-186-3')

try:
    vr.verify(h, sig)
    print("OK")
except ValueError:
    print("ERR")
