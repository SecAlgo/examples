from sa.secalgoB import keygen, encrypt, decrypt, sign, verify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC

MAX_SKIP = 100

class state():
    def __init__(self):
        state.DHs = None # DH Ratchet key pair (the "sending" or "self" ratchet key)
        state.DHr = None # DH Ratchet public key (the "received" or "remote" key)
        state.RK = None  # 32-byte Root Key
        state.CKs = None # 32-byte Chain Key for sending 
        state.CKr = None # 32-byte Chain Key for receiving
        state.Ns = None  # Message numbers for sending
        state.Nr = None  # Message numbers for receiving
        state.PN = None  # Number of messages in previous sending chain
        # Dictionary of skipped-over message keys,
        # indexed by ratchet public key and
        # message number. Raises an exception if too many
        # elements are stored.
        state.MKSKIPPED = None
    #end def __init()__
#end class state

class Header():
    def __init__(self, dh_pair, pn, n):
        self.dh = dh_pair.public_key().public_bytes()
        self.pn = pn
        self.n = n
    #end def __init__()

    def __str__(self):
        return ('dh: ' + str(self.dh) +
                ', pn: ' + str(self.pn) +
                ', n: ' + str(self.n))
    #end def __str__()
#end class Header()

def GENERATE_DH():
    #keygen('ECC', curve = 'X21599')
    return X25519PrivateKey.generate()
#end def GENERATE_DH()

def DH(dh_pair, dh_pub):
    return dh_pair.exchange(X25519PublicKey.from_public_bytes(dh_pub))
#end def DH()

def KDF_RK(rk, dh_out):
    kd = HKDF(algorithm = hashes.SHA256(),
              length=64,
              salt = rk,
              info = b'kdf_rk_info',
              backend = default_backend())
    kd_out = kd.derive(dh_out)
    root_key = kd_out[:32]
    chain_key = kd_out[32:]
    return root_key, chain_key
#end def KDF_RK()

def KDF_CK(ck):
    ck_h = HMAC(ck, hashes.SHA256(), backend = default_backend())
    ck_h.update(b'\1')
    chain_key = ck_h.finalize()
    mk_h = HMAC(ck, hashes.SHA256(), backend = default_backend())
    mk_h.update(b'\2')
    message_key = mk_h.finalize()
    return chain_key, message_key
#end def KDF_CK()

def ENCRYPT(mk, plaintext, associated_data):
    kd = HKDF(algorithm = hashes.SHA256(),
              length = 80,
              salt = (b'\0' * 32),
              info = b'kdf_encrypt_info',
              backend = default_backend())
    kd_out = kd.derive(mk)
    enc_key = keygen('shared', key_mat = kd_out[:32])
    auth_key = keygen('mac', key_mat = kd_out[32:64])
    kd_iv = kd_out[64:]
    ct = encrypt(plaintext, key = enc_key, iv = kd_iv)
    data, mac = sign(associated_data + ct, key = auth_key)
    #print('E-KDF:', kd_out)
    #print('E-data:', data)
    #print('E-AD:', associated_data)
    #print('E-CT:', ct)
    #print('E-MAC: ', mac)
    #print()
    return ct + mac
#end def ENCRYPT()

def DECRYPT(mk, ciphertext, associated_data):
    kd = HKDF(algorithm = hashes.SHA256(),
              length = 80,
              salt = (b'\0' * 32),
              info = b'kdf_encrypt_info',
              backend = default_backend())
    kd_out = kd.derive(mk)
    
    enc_key = keygen('shared', key_mat = kd_out[:32])
    auth_key = keygen('mac', key_mat = kd_out[32:64])
    kd_iv = kd_out[64:]
    ct_iv = ciphertext[:16]
    ct_mac = ciphertext[-32:]
    ct = ciphertext[:-32]
    #print('D-KDF:', kd_out)
    #print('D-AD:', associated_data)
    #print('D-CT:', ct)
    #print('D-MAC', ct_mac)
    assert kd_iv == ct_iv
    verdict = verify((b'\0' + associated_data + ct, ct_mac), key = auth_key)
    if verdict != None:
        return decrypt(ct, key = enc_key)
    else:
        raise Exception()
#end def DECRYPT()

def HEADER(dh_pair, pn, n):
    return Header(dh_pair, pn, n)
#end def HEADER()

def CONCAT(ad, header):
    pubk_as_bytes = header.dh
    # fixing the max value for pn and n as 65535
    pn_as_bytes = header.pn.to_bytes(2, byteorder = 'big')
    n_as_bytes = header.n.to_bytes(2, byteorder = 'big')
    ad_length = len(ad)
    ad_length_as_bytes = ad_length.to_bytes(2, byteorder = 'big')
    return ad + pubk_as_bytes + pn_as_bytes + n_as_bytes
#end def CONCAT()
    
def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key.public_bytes()
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MSKIPPED = dict()
#end def RatchetInitAlice()

def RatchetInitBob(state, SK, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MSKIPPED = dict()
#end def RatchetInitBob()

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, header.n) in state.MSKIPPED:
        mk = state.MSKIPPED[header.dh, header.n]
        del state.MSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None
#end def TrySkippedMessageKeys()

def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Exception()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MSKIPPED[state.DHr, state.Nr] = mk
            state.Nr += 1
#end def SkippedMessageKeys()

def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
#end DHRatchet

def RatchetEncrypt(state, plaintext, AD):
    state.CKs, mk = KDF_CK(state.CKs)
    header = HEADER(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
#end def RatchetEncrypt()

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    if header.dh != state.DHr:
        SkipMessageKeys(state, header.pn)
        DHRatchet(state, header)
    SkipMessageKeys(state, header.n)
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1
    return DECRYPT(mk, ciphertext, CONCAT(AD, header))
#end def RatchetDecrypt()

if __name__ == '__main__':
    SK = keygen('random', 32)
    AD = keygen('random', 32)
    bob_init_key_pair = GENERATE_DH()
    bob_init_pubk = bob_init_key_pair.public_key()
    alice_state = state()
    bob_state = state()
    RatchetInitAlice(alice_state, SK, bob_init_pubk)
    RatchetInitBob(bob_state, SK, bob_init_key_pair)
    msg1 = b'I am a secret.'
    print('Message 1:', msg1)
    msg1_header, msg1_ct = RatchetEncrypt(alice_state, msg1, AD)
    print('Header 1:', msg1_header)
    print('Encrypted 1:', msg1_ct)
    msg1_pt = RatchetDecrypt(bob_state, msg1_header, msg1_ct, AD)
    print('Decrypted 1:', msg1_pt)
    msg2 = b'I am also a secret.'
    print('Message 2:', msg2)
    msg2_header, msg2_ct = RatchetEncrypt(bob_state, msg2, AD)
    print('Header 2:', msg2_header)
    print('Encrypted 2:', msg2_ct)
    msg2_pt = RatchetDecrypt(alice_state, msg2_header, msg2_ct, AD)
    print('Decrypted 2:', msg2_pt)
