from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import struct
import sys
from utils import point2binary, binary2key, validate_sig, generate_sig


if len(sys.argv) > 1 and sys.argv[1][0] == 'g':
    key = ECC.generate(curve='secp256r1')
    keyfile = sys.argv[2]
    with open(keyfile, 'wb') as f:
        f.write(key.export_key(format='DER', compress=False))
    k = point2binary(key.pointQ)
    print("Voter public key: {}".format(k.hex()))
    exit(0)

keyfile = sys.argv[1]
with open(keyfile, 'rb') as f:
    key = ECC.import_key(f.read())

spk = input("Input VE public key: ")
spk = bytes.fromhex(spk)
spk = binary2key(spk)

vid = input("Input VID: ")
vid = bytes.fromhex(vid)
o = input("Input option: ")
o = int(o)

vote = point2binary(key.pointQ) + vid + struct.pack("<I", o)

h = SHA256.new(vote)
sig = generate_sig(key, h)

dh_key = ECC.generate(curve='secp256r1')


shared_sec = (spk.pointQ * dh_key.d).x.to_bytes(32)
salt = get_random_bytes(16)
aes_key = PBKDF2(shared_sec, salt, 32, count=1000, hmac_hash_module=SHA256)

pt = vote + sig

cip = AES.new(aes_key, AES.MODE_CBC)
ct = cip.encrypt(pad(pt, AES.block_size))

msg = point2binary(dh_key.pointQ) + salt + cip.iv + ct
print("Encrypted vote: " + msg.hex())


vvr = input("Input VVR: ")
vvr = bytes.fromhex(vvr)
if len(vvr) < 16 or len(vvr) % 16 != 0:
    print("Invalid encrypted VVR length!")
    exit(1)
cip = AES.new(aes_key, AES.MODE_CBC, vvr[:16])
vvr = unpad(cip.decrypt(vvr[16:]), AES.block_size)

if len(vvr) != 65 + 32 + 4 + 32 + 64:
    print("Invalid VVR length!\n")
    exit(1)
rv = vvr[:-64]
sig = vvr[-64:]

h = SHA256.new(rv)
print("hash(RV): " + h.hexdigest())
h = SHA256.new(h.digest())
h.update(vid)

if validate_sig(spk, h, sig):
    print("VVR Signature OK")
else:
    print("Invalid VVR signature!")
    exit(1)

if rv[:65] == point2binary(key.pointQ):
    print("VVR voter public key OK (is ours)")
else:
    print("VVR voter public key OK is invalid!")
    exit(1)

if rv[65:65+32] == vid:
    print("VVR VID OK")
else:
    print("VVR VID invalid!")
    exit(1)

if rv[65+32:-32] == struct.pack("<I", o):
    print("VVR voter option OK")
else:
    print("VVR voter option invalid!")
    exit(1)

print("VVR verified correctly")
exit(0)
