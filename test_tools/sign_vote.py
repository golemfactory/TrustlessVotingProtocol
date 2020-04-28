from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
from Crypto.Util.Padding import pad, unpad
import struct
import sys


def point2pk(p):
    return b'\x04' + p.x.to_bytes(32) + p.y.to_bytes(32)

if len(sys.argv) > 1 and sys.argv[1][0] == 'g':
    key = ECC.generate(curve='secp256r1')
    with open('mykey.der', 'wb') as f:
        f.write(key.export_key(format='DER', compress=False))
    k = point2pk(key.pointQ)
    print("Public key: {}".format(k.hex()))
    exit(0)

with open('mykey.der', 'rb') as f:
    key = ECC.import_key(f.read())

spk = input("Server public key: ")
spk = bytes.fromhex(spk)
der_key = b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
der_key += spk
spk = ECC.import_key(der_key)

v = input("Input vid: ")
v = bytes.fromhex(v)
o = input("Input option: ")
o = int(o)

vote = point2pk(key.pointQ) + v + struct.pack("<I", o)

h = SHA256.new(vote)
signer = DSS.new(key, 'fips-186-3')
sig = signer.sign(h)

dh_key = ECC.generate(curve='secp256r1')


shared_sec = (spk.pointQ * dh_key.d).x.to_bytes(32)
salt = get_random_bytes(16)
aes_key = PBKDF2(shared_sec, salt, 32, count=1000, hmac_hash_module=SHA256)

pt = vote + sig

cip = AES.new(aes_key, AES.MODE_CBC)
ct = cip.encrypt(pad(pt, AES.block_size))

msg = point2pk(dh_key.pointQ) + salt + cip.iv + ct
print("Encrypted vote: " + msg.hex())


vvr = input("Input VVR: ")
vvr = bytes.fromhex(vvr)
if len(vvr) < 16 or len(vvr) % 16 != 0:
    print("Invalid encrypted VVR length!")
    exit(1)
cip = AES.new(aes_key, AES.MODE_CBC, vvr[:16])
vvr = unpad(cip.decrypt(vvr[16:]), AES.block_size)

if len(vvr) != 65 + 32 + 4 + 32 + 64:
    print("Invalid vvr length!\n")
    exit(1)
rv = vvr[:-64]
sig = vvr[-64:]

h = SHA256.new(rv)
h = SHA256.new(h.digest())
h.update(v)
vr = DSS.new(spk, 'fips-186-3')
try:
    vr.verify(h, sig)
    print("Signature OK")
except ValueError:
    print("Invalid signature!")
    exit(1)

if rv[:65] == point2pk(key.pointQ):
    print("VVR voter public key OK (is ours)")
else:
    print("VVR voter public key OK is invalid!")
    exit(1)

if rv[65:65+32] == v:
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
