import struct
from Crypto.Hash import SHA256
from utils import binary2key, validate_sig


p = input("Input VDEH path (empty for default): ")
if not p:
    p = "vdeh.tvp"

with open(p, "rb") as f:
    x = f.read()

start_time = x[:32]
end_time = x[32:64]
num_options = struct.unpack("<I", x[64:68])[0]
num_voters = struct.unpack("<I", x[68:72])[0]
voters = []
i = 72
for _ in range(num_voters):
    pk = x[i:i+65]
    i += 65
    w = struct.unpack("<I", x[i:i+4])[0]
    i += 4
    voters.append((pk, w))
ds = struct.unpack("<Q", x[i:i+8])[0]
i += 8
description = x[i:i+ds]
i += ds

nonce = x[i:i+32]
i += 32
ve_sig = x[i:i+64]
i += 64
eh_sig = x[i:i+64]
i += 64
ve_pubkey = x[i:i+65]
i += 65

h = SHA256.new()
h.update(nonce)
h.update(start_time)
h.update(end_time)
h.update(struct.pack("<I", num_options))
h.update(struct.pack("<I", len(voters)))
for v in voters:
    h.update(v[0])
    h.update(struct.pack("<I", v[1]))
h.update(struct.pack("<Q", len(description)))
h.update(description)

vid =  h.hexdigest()

if validate_sig(binary2key(ve_pubkey), h, ve_sig):
    print("VE signature OK")
else:
    print("VE signature ERR")
    exit(1)

eh_pubkey = bytes.fromhex(input("Input EH pubkey: "))
assert len(eh_pubkey) == 65

h = SHA256.new()
# VD
h.update(start_time)
h.update(end_time)
h.update(struct.pack("<I", num_options))
h.update(struct.pack("<I", len(voters)))
for v in voters:
    h.update(v[0])
    h.update(struct.pack("<I", v[1]))
h.update(struct.pack("<Q", len(description)))
h.update(description)
# VDVE
h.update(nonce)
h.update(ve_sig)

if validate_sig(binary2key(eh_pubkey), h, eh_sig):
    print("EH signature OK")
else:
    print("EH signature ERR")
    exit(1)

print("VID: " + vid)
