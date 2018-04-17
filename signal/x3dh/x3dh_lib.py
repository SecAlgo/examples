from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from nacl.public import Box
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256

X25519 = B'\0'

def keygen():
    privk = SigningKey.generate()
    pubk = privk.verify_key
    return privk, pubk

def encode(K):
    return X25519 + K.encode(encoder = HexEncoder)

def decode(EK):
    return VerifyKey(EK[1:], encoder = HexEncoder)

def dh(KP_L, PK_R):
    privk_L = KP_L.to_curve25519_private_key()
    pubk_R = PK_R.to_curve25519_public_key()
    box_LR = Box(privk_L, pubk_R)
    return box_LR.shared_key()

def sign(KP, M):
    return KP.sign(M)

def verify(PK, M):
    return PK.verify(M)

def kdf(KM):
    F = b'\xff' * 32
    s = b'\0' * 32
    info = b'x3dh info'
    return HKDF(KM, salt = s, key_len = 32,
                hashmod = SHA256.new(), context = info)


