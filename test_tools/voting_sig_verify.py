import struct
from Crypto.Hash import SHA256
from utils import binary2key, validate_sig


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

key = binary2key(k)
if validate_sig(key, h, sig):
    vr.verify(h, sig)
    print("OK")
else:
    print("ERR")
    exit(1)
