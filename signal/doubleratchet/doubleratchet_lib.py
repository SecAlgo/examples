from doubleratchet_ext import (MAX_SKIP, GENERATE_DH, DH, KDF_RK, KDF_CK,
                               ENCRYPT, DECRYPT, HEADER, CONCAT)

# Sources:
# [1] - "The Double Ratchet Algorithm", Trevor Perrin, Moxie Marlinspike.
#       https://signal.org/docs/specifications/doubleratchet/
#       Revision 1.0, 11/20/2016

# Copyright Open Whisper Systems 2013 - 2018
# Moxie Marlinspike, Trevor Perrin

# Double Ratchet functions: For each of these functions the specification in
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
