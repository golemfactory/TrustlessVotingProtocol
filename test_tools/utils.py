from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def point2binary(p):
    return b'\x04' + p.x.to_bytes(32) + p.y.to_bytes(32)

def binary2key(x):
    der = b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
    return ECC.import_key(der + x)

def validate_sig(key, h, sig):
    vr = DSS.new(key, 'fips-186-3')
    try:
        vr.verify(h, sig)
        return True
    except ValueError:
        return False

def generate_sig(key, h):
    signer = DSS.new(key, 'fips-186-3')
    return signer.sign(h)
