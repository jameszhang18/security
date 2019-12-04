import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1,"big")) + tmp)

def is_admin_cookie(decrypted_cookie):
    return decrypted_cookie[0] == 1

class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)
        if in_key is None:
            self._key = os.urandom(self._block_size_bytes)
        else:
            self._key = in_key

    # reference: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
    def encrypt(self, key, plaintext, associated_data=b"authenticated but not encrypted payload"):
        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return (iv + encryptor.tag + ciphertext)

    def decrypt(self, ciphertext, associated_data=b"authenticated but not encrypted payload"):
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        iv, tag, ciphertext = ciphertext[:self._block_size_bytes], ciphertext[self._block_size_bytes:2*self._block_size_bytes],ciphertext[2*self._block_size_bytes:]

        decryptor = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()
        
    # def encrypt(self, msg):
    #     padder = padding.PKCS7(ciphers.algorithms.AES.block_size).padder()
    #     padded_msg = padder.update(msg) + padder.finalize()
    #     iv = os.urandom(self._block_size_bytes)
    #     encryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
    #                                ciphers.modes.CBC(iv),
    #                                self._backend).encryptor()
    #     _ciphertext = iv + encryptor.update(padded_msg) + encryptor.finalize()
    #     return _ciphertext
    
    # def decrypt(self, ctx):
    #     iv, ctx = ctx[:self._block_size_bytes], ctx[self._block_size_bytes:]
    #     unpadder = padding.PKCS7(ciphers.algorithms.AES.block_size).unpadder()
    #     decryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
    #                                ciphers.modes.CBC(iv),
    #                                self._backend).decryptor()        
    #     padded_msg = decryptor.update(ctx) + decryptor.finalize()
    #     try:
    #         msg = unpadder.update(padded_msg) + unpadder.finalize()
    #         return msg  # Successful decryption
    #     except ValueError:
    #         return False  # Error!!

    

        
if __name__=='__main__':
    test_encr_decr()
