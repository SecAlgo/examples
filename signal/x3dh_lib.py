from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from nacl.public import Box
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
import sa.secalgoB as SA

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

def encrypt(k, pt, ad):
    kd_out = HKDF(k, salt = (b'\0' * 32), key_len = 80,
                  hashmod = SHA256.new(), context = b'kdf_encrypt_info')
    enc_key = SA.keygen('shared', key_mat = kd_out[:32])
    auth_key = SA.keygen('mac', key_mat = kd_out[32:64])
    kd_iv = kd_out[64:]
    ct = SA.encrypt(pt, key = enc_key, iv = kd_iv)
    data, mac = SA.sign(ad + ct, key = auth_key)
    return ct + mac

def decrypt(k, ct, ad):
    kd_out = HKDF(k, salt = (b'\0' * 32), key_len = 80,
                  hashmod = SHA256.new(), context = b'kdf_encrypt_info')
    enc_key = SA.keygen('shared', key_mat = kd_out[:32])
    auth_key = SA.keygen('mac', key_mat = kd_out[32:64])
    kd_iv = kd_out[64:]
    ct_iv = ct[:16]
    ct_mac = ct[-32:]
    ct_ct = ct[:-32]
    assert kd_iv == ct_iv
    verdict = SA.verify((b'\0' + ad + ct_ct, ct_mac), key = auth_key)
    if verdict != None:
        return SA.decrypt(ct_ct, key = enc_key)
    else:
        raise Exception
    
