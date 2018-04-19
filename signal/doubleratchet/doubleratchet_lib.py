from sa.secalgoB import keygen, encrypt, decrypt, sign, verify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC

# Sources:
# [1] - "The Double Ratchet Algorithm", Trevor Perrin, Moxie Marlinspike.
#       https://signal.org/docs/specifications/doubleratchet/
#       Revision 1.0, 11/20/2016

# The maximum number of message keys that can be skipped in a single chain.
# It should be set high enough to tolerate routine lost or delayed messages,
# but low enough that a malicious sender can't trigger excessive recipient
# computation. [1], p. 18
MAX_SKIP = 100


# State class defines an object containing the state variables that must be
# tracked by each party to the double ratchet protocol. [1], p. 19
class state():
    def __init__(self):
        state.DHs = None # DH Ratchet key pair (the "sending" or "self" ratchet key)
        state.DHr = None # DH Ratchet public key (the "received" or "remote" key)
        state.RK = None  # 32-byte Root Key
        state.CKs = None # 32-byte Chain Key for sending 
        state.CKr = None # 32-byte Chain Key for receiving
        state.Ns = None  # Message number for sending
        state.Nr = None  # Message number for receiving
        state.PN = None  # Number of messages in previous sending chain
        # Dictionary of skipped-over message keys, indexed by ratchet public
        # key and message number. Raises an exception if too many elements are
        # stored.
        state.MKSKIPPED = None
    #end def __init()__
#end class state

# Header class defines objects returned by the HEADER function, implemented
# below, and contains fields for the ratchet public key, "dh", the length
# of the previous sending chain, "pn", and the message number of this sent
# message for which this is the header, "n". [1], p. 18-19
class Header():
    def __init__(self, dh_pair, pn, n):
        self.dh = dh_pair.public_key().public_bytes() # Ratchet public key
        self.pn = pn # Number of messages in previous sending chain
        self.n = n # Message number for this message
    #end def __init__()

    # This returns a very boring string representation of a header object
    # for debugging purposes. This is not mentioned in [1]. 
    def __str__(self):
        return ('dh: ' + str(self.dh) +
                ', pn: ' + str(self.pn) +
                ', n: ' + str(self.n))
    #end def __str__()
#end class Header()

# External functions: "To instantiate the Double Ratchet requires defining the
# following functions", [1], p. 18. The specification provides function headers
# and descriptions for these functions, but does not include implementation.
# The implementation was done by us based on their security annd cryptographic
# recommendations on p.30 of [1].

# GENERATE_DH(): Returns a new Diffie-Hellman key pair. [1], p. 18
# This function is recommended to generate a key pair based on the Curve25519
# or Curve448 elliptic curves. [1], p. 30.
def GENERATE_DH():
    #keygen('ECC', curve = 'X21599')
    return X25519PrivateKey.generate()
#end def GENERATE_DH()

# DH(dh_pair, dh_pub): Returns the output from the Diffie-Hellman calculation
# between the private key from the DH key pair "dh_pair" and the DH public key
# "dh_pub". If the DH function rejects invalid public keys, then this function
# may raise an exception which terminates processing. [1], p. 18.
# This function is recommended to return the output from the X25519 or X448
# function as defined in RFC 7748. There is no need to check for invalid public
# keys. [1], p. 30.
def DH(dh_pair, dh_pub):
    return dh_pair.exchange(X25519PublicKey.from_public_bytes(dh_pub))
#end def DH()

# KDF_RK(rk, dh_out): Returns a pair (32-byte root key, 32-byte chain key) as
# the output of applying a KDF keyed by a 32-byte root key "rk", to a
# Diffie-Hellman output "dh_out". [1], p. 18.
# This function is recommended to be implemented using HKDF with SHA-256 or
# SHA-512, using "rk" as HKDF "salt", "dh_out" as HKDF "input key material",
# and an application-specific byte sequence as HKDF "info". The "info" value
# should be chosen to be distinct from other uses of HKDF in this
#application. [1], p. 30
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

# KDF_CK(ck): Returns a pair (32-byte chain key, 32-byte message key) as the
# output of applying a KDF keyed by a 32-byte chain key "ck" to some
# constant. [1], p. 18
# HMAC with SHA-256 or SHA-512 is recommended, using ck as the HMAC key and
# using separate constants as input (e.g. a single byte 0x01 as input to
# produce the message key, and a single byte 0x02 as input to produce the next
# chain key. [1], p. 30
def KDF_CK(ck):
    ck_h = HMAC(ck, hashes.SHA256(), backend = default_backend())
    ck_h.update(b'\1')
    chain_key = ck_h.finalize()
    mk_h = HMAC(ck, hashes.SHA256(), backend = default_backend())
    mk_h.update(b'\2')
    message_key = mk_h.finalize()
    return chain_key, message_key
#end def KDF_CK()

# ENCRYPT(mk, plaintext, associated_data): Returns an AEAD encryption of
# "plaintext" with message key "mk". The "associate_data" is authenticated
# but is not included in the ciphertext. Because each message is key is used
# only once , the AEAD nonce may be handled in several ways: fixed to a
# constant; derived from "mk" alongside an independent AEAD encryption key;
# derived as an additional output from KDF_CK(); or chosen randomly and
# transmitted. [1], p. 18
# This function is recommended to be implemented with an AEAD encryption scheme
# based on either SIV or a composition of CBC with HMAC. These schemes provide
# some misuse-resistance in case a key is mistakenly used multiple times. A
# concrete recommendation based on CBC and HMAC is as follows:
#  -HKDF is used with SHA-256 or SHA 512 to generate 80 bytes of output. The
#   HKDF "salt" is set to a zero-filled byte sequence equal to the hash's
#   output length. HKDF "input key material" is set to "mk". HKDF "info" is
#   set to an application-specific byte sequence distinct from other uses of
#   HKDF in the application.
#  -The HKDF output is divided into a 32-byte encryption key, a 32-byte
#   authentication key, and a 16-byte IV.
#  -The plaintext is encrypted used AES-256 in CBC mode with PCKS#7 padding,
#   using the encryption key and IV from the previous step.
#  -HMAC is calculated using the authentication key and the same hash function
#   as above. The HMAC input is the "associated_data" prepended to the
#   ciphertext. The HMAC output is appended to the ciphertext.
# [1], p. 30
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
    return ct + mac
#end def ENCRYPT()

# DECRYPT(mk, ciphertext, associated_data): Returns the AEAD decryption of
# "ciphertext" with message key "mk". If authentication fails, as exception
# will be raised that terminates processing.
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
    assert kd_iv == ct_iv
    verdict = verify((b'\0' + associated_data + ct, ct_mac), key = auth_key)
    if verdict != None:
        return decrypt(ct, key = enc_key)
    else:
        raise Exception()
#end def DECRYPT()

# HEADER(dh_pair, pn, n): Creates a new message header containing the DH
# ratchet public key from the key pair in "dh_pair", the previous chain length
# "pn", and the message number n. The returned header object contains ratchet
# public key "dh", and integers "pn" and "n". [1], p. 18
def HEADER(dh_pair, pn, n):
    return Header(dh_pair, pn, n)
#end def HEADER()

# CONCAT(ad, header): Encodes a message header into a parseable byte sequence,
# prepends the "ad" byte sequence, and returns the result. If "ad" is not
# guaranteed to be a parsable byte sequence, a length value should be prepended
# to the output to ensure that the output is parseable as a unique pair
# ("ad", "header"). [1], p. 18
def CONCAT(ad, header):
    pubk_as_bytes = header.dh
    # CMK: fixing the max value for pn and n as 65535 bytes
    pn_as_bytes = header.pn.to_bytes(2, byteorder = 'big')
    n_as_bytes = header.n.to_bytes(2, byteorder = 'big')
    ad_length = len(ad)
    # CMK: same for length of ad
    ad_length_as_bytes = ad_length.to_bytes(2, byteorder = 'big')
    return ad + pubk_as_bytes + pn_as_bytes + n_as_bytes
#end def CONCAT()

# End External Functions

# Double Ratchet functions: For each of these functions the specificaiton in
# [1] includes a Python implementation, which is reproduced unchanged below.
# The description and implementation of these functions is given
# in [1], pp. 19-21

# Uses a previously established shared secret key and Bob's ratchet public key
# to generate Alice's initial root key and sending chain key. This assumes
# that Alice will send the first message. [1], p. 19
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

# Uses a previously established shared secret key and Bob's ratchet key pair,
# Bob initializes his stated, with the shared secret key as the initial root
# key. This will be updated by a Diffie-Hellman ratchet when Bob received an
# initial message from Alice. This assumes that Alice will send the first
# message. [1], p. 20
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

# This method checks to see whether an entry indexed by the ratchet public key
# and message number in the header of a received message has been added to the
# "MSKIPPED" dictionary in the receiver's state--testing whether this message
# has arrived out of order, and using a stored message key to decrypt the
# message. [1], p. 21 
def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, header.n) in state.MSKIPPED:
        mk = state.MSKIPPED[header.dh, header.n]
        del state.MSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None
#end def TrySkippedMessageKeys()

# Uses the message number in the header of the received message ("until") to
# determine whether this message has arrived out of order (before other
# messages that were sent earlier). If so, and if the difference between the
# last received message number and the current message number is less than the
# MAX_SKIP value, then the symmetric chain ratchet will be used to generate
# intermediate message keys for the skipped over messages to be added to the
# MSKIPPED dictionary, so that we will then be able to generate the message key
# for the currently received message. [1], p. 21
def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Exception()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MSKIPPED[state.DHr, state.Nr] = mk
            state.Nr += 1
#end def SkippedMessageKeys()

# DHRatchet performs an update of the receiver's root key and their receiving
# chain key incorporating the ratchet public key value included in the header
# of the received message. The root key and the sending chain key are also then
# ratcheted forward using the newly received ratchet public key value from the
# recevied message header and a new ratchet key pair value generated locally by
# the receiver.
# This function also resets the message number values to zero to represent that
# a new message chain is begun by the Diffie-Hellman ratchet of the root and
# chain keys. The length of the chain that just ended is assigned as the new
# value for the "PN" state variable. [1], p. 21
def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
#end DHRatchet

# This function performs a symmetric-key ratchet to update the sending
# chain key and a new message key. We also construct a header object for the
# message and update the sent message number. The message key is used to
# encrypt plaintext, passing the conctatenation of AD and the serialized header
# as the associated data for AEAD encryption.
# Ratchet encrypt returns a pair of the header object for this message and the
# ciphertext.
def RatchetEncrypt(state, plaintext, AD):
    state.CKs, mk = KDF_CK(state.CKs)
    header = HEADER(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
#end def RatchetEncrypt()

# This function is called when a message is received. The first test determines
# whether this message has arrived out-of-order, and if so, finds the
# appropriate message key from the MSKIPPED dictionary, uses it to decrypt the
# message, and returns the plaintext.
# It then checks to see if the message header contains a new ratchet public key
# from the correspondent. If so, then if this message has arrived out-of-order,
# then it generates keys for all the intermediate messages from the previous
# message change, that have yet to arrive, and then performs a Diffie-Hellman
# ratchet to update the root key and chain keys to incorporate the new public
# key value.
# Whether or not a new ratchet public key is provided, the receiver must then
# generate keys for any missed messages on the new message chain, and then
# ratchet the receiving chain key and message key forward, increment the
# received message number, and then decrypt the message with the new message
# key. [1], pp. 20-21
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

# small local test program for the double ratchet
def main():
    # The initial shared secret key is assumed to be the product of some prior
    # protocol exchange. The specification recommends the use of the Extended
    # Triple Diffie-Hellman (X3DH) protocol, which will generate both the
    # shared secret key and AD, where the value of AD will be derived from the
    # identifiers for the processes corresponding through the double ratchet.
    SK = keygen('random', 32) # initial shared secret
    AD = keygen('random', 32) # random simulated AD value
    bob_init_key_pair = GENERATE_DH() # generate Bob's initial ratchet key pair
    bob_init_pubk = bob_init_key_pair.public_key() # get public part
    alice_state = state() # create sender state
    bob_state = state() # create receiver state
    RatchetInitAlice(alice_state, SK, bob_init_pubk) # set-up sender state
    RatchetInitBob(bob_state, SK, bob_init_key_pair) # set-up receiver state
    msg1 = b'I am a secret.' # some message
    print('Message 1:', msg1)
    # Alice encrypts first message, getting back header and ciphertext
    msg1_header, msg1_ct = RatchetEncrypt(alice_state, msg1, AD)
    print('Header 1:', msg1_header)
    print('Encrypted 1:', msg1_ct)
    # Bob decrypts the first message
    msg1_pt = RatchetDecrypt(bob_state, msg1_header, msg1_ct, AD)
    print('Decrypted 1:', msg1_pt)
    msg2 = b'I am also a secret.'
    print('Message 2:', msg2)
    # Bob encrypts second message
    msg2_header, msg2_ct = RatchetEncrypt(bob_state, msg2, AD)
    print('Header 2:', msg2_header)
    print('Encrypted 2:', msg2_ct)
    # Alice decrypts seconds message
    msg2_pt = RatchetDecrypt(alice_state, msg2_header, msg2_ct, AD)
    print('Decrypted 2:', msg2_pt)

if __name__ == '__main__':
    main()
