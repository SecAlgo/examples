from nacl.encoding import HexEncoder
import doubleratchet_ext as EXT
import doubleratchet_lib as DR
from sa.secalgoB import keygen

# Sources:
# [1] - "The Double Ratchet Algorithm", Trevor Perrin, Moxie Marlinspike.
#       https://signal.org/docs/specifications/doubleratchet/
#       Revision 1.0, 11/20/2016

# small test program for the double ratchet
def main():
    # The initial shared secret key is assumed to be the product of some prior
    # protocol exchange. The specification recommends the use of the Extended
    # Triple Diffie-Hellman (X3DH) protocol, which will generate both the
    # shared secret key and AD, where the value of AD will be derived from the
    # identifiers for the processes corresponding through the double ratchet.
    SK = keygen('random', 32) # initial shared secret
    AD = keygen('random', 32) # random simulated AD value
    bob_init_key_pair = EXT.GENERATE_DH() # generate Bob's initial ratchet key pair
    # get public part
    bob_init_pubk = bob_init_key_pair.verify_key.encode(encoder = HexEncoder) 
    alice_state = EXT.state() # create sender state
    bob_state = EXT.state() # create receiver state
    DR.RatchetInitAlice(alice_state, SK, bob_init_pubk) # set-up sender state
    DR.RatchetInitBob(bob_state, SK, bob_init_key_pair) # set-up receiver state
    msg1 = b'I am a secret.' # some message
    print('Message 1:', msg1)
    # Alice encrypts first message, getting back header and ciphertext
    msg1_header, msg1_ct = DR.RatchetEncrypt(alice_state, msg1, AD)
    print('Header 1:', msg1_header)
    print('Encrypted 1:', msg1_ct)
    # Bob decrypts the first message
    msg1_pt = DR.RatchetDecrypt(bob_state, msg1_header, msg1_ct, AD)
    print('Decrypted 1:', msg1_pt)
    msg2 = b'I am also a secret.'
    print('Message 2:', msg2)
    # Bob encrypts second message
    msg2_header, msg2_ct = DR.RatchetEncrypt(bob_state, msg2, AD)
    print('Header 2:', msg2_header)
    print('Encrypted 2:', msg2_ct)
    # Alice decrypts seconds message
    msg2_pt = DR.RatchetDecrypt(alice_state, msg2_header, msg2_ct, AD)
    print('Decrypted 2:', msg2_pt)

if __name__ == '__main__':
    main()
