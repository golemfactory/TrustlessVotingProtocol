from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import struct


k = input("Input server pubkey: ")
k = bytes.fromhex(k)
assert len(k) == 65
n = input("Input nonce: ")
n = bytes.fromhex(n)
sig = input("Input sig: ")
sig = bytes.fromhex(sig)

h = SHA256.new()
h.update(n)
x = input("Input start time: ").encode('utf-8')
assert len(x) <= 32
h.update(x.ljust(32, b'\x00'))
x = input("Input end time: ").encode('utf-8')
assert len(x) <= 32
h.update(x.ljust(32, b'\x00'))

no = input("Input number of options: ")
no = int(no)
h.update(struct.pack("<I", no)) # num_options

vn = input("Input number of voters: ")
vn = int(vn)
h.update(struct.pack("<I", vn)) # num_voters
for i in range(vn):
    vk = input("Input voter pubkey: ")
    vk = bytes.fromhex(vk)
    h.update(vk)
    vw = input("Input voter weight: ")
    vw = int(vw)
    h.update(struct.pack("<I", vw)) # voter weight

desc = input("Input description: ").encode('utf-8')
h.update(struct.pack("<Q", len(desc)))
h.update(desc)

print("VID: " + h.hexdigest())

der_key = b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
der_key += k

key = ECC.import_key(der_key)
vr = DSS.new(key, 'fips-186-3')

try:
    vr.verify(h, sig)
    print("OK")
except ValueError:
    print("ERR")
