from Crypto.Hash import SHA256
from utils import binary2key, validate_sig
import struct


vreh = input("Input VREH: ")
vreh = bytes.fromhex(vreh)
vrve = vreh[:-64]
sig = vreh[-64:]

x = input("Input EH public key: ")
eh_pubkey = binary2key(bytes.fromhex(x))

h = SHA256.new(vrve)
if validate_sig(eh_pubkey, h, sig):
    print("VREH signature OK")
else:
    print("Invalid VREH signature!")
    exit(1)

x = input("Input VE public key: ")
ve_pubkey = binary2key(bytes.fromhex(x))
sig = vrve[-64:]
vrve = vrve[:-64]

h = SHA256.new(vrve)
if validate_sig(ve_pubkey, h, sig):
    print("VRVE signature OK")
else:
    print("Invalid VRVE signature!")
    exit(1)

x = input("Input VID: ")
vid_expected = bytes.fromhex(x)
if vid_expected == vrve[:32]:
    print("VID in VREH matches")
else:
    print("VID in VREH does not match!")
    exit(1)

num_options = struct.unpack("<I", vrve[32:36])[0]
res_end = 36 + num_options * 4
results = vrve[36:res_end]

num_votes = struct.unpack("<Q", vrve[res_end:res_end+8])[0]
votes = vrve[res_end+8:]

hrv = input("Input your RV hash: ")
hrv = bytes.fromhex(hrv)

found = False
for i in range(num_votes):
    if votes[i*32:(i+1)*32] == hrv:
        found = True
        break

if found:
    print("Your vote was counted")
else:
    print("Your vote was NOT counted!!!")
    exit(1)

print("Voting results:")
for i in range(num_options):
    x = struct.unpack("<I", results[i*4:(i+1)*4])[0]
    print("{:2d}: {:d}".format(i+1, x))
