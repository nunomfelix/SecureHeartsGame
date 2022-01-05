import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class sym_crypto:

    def __init__(self,algoritm):
        self.key = os.urandom(16)
        self.sym_iv = os.urandom(16)
        self.algoritm = algoritm
        self.cipher = self.generate_cipher(self.key, self.sym_iv)

    def generate_cipher(self, key,iv):
        if self.algoritm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        elif self.algoritm == 'Camellia':
            cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), default_backend())
        elif self.algoritm == 'IDEA':
            cipher = Cipher(algorithms.IDEA(key), modes.ECB(), default_backend())
        elif self.algoritm == 'CAST5':
            cipher = Cipher(algorithms.CAST5(key), modes.ECB(), default_backend())
        elif self.algoritm == 'SEED':
            cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), default_backend())
        elif self.algoritm == 'BlowFish':
            cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), default_backend())
        return cipher

    def decrypt(self,message,key,iv):
        cipher = self.generate_cipher(key,iv)
        decryptor = cipher.decryptor()
        return decryptor.update(message)

    def encrypt(self,message):
        encryptor = self.cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()
        return ct

    