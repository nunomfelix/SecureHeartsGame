import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils, ec
from cryptography.exceptions import InvalidSignature

class RSA:

    def __init__(self,name):
        self.priv_file = ''
        self.pub_file = ''
        self.priv_key = ''
        self.pub_key = ''
        self.generate_priv(name)
        self.generate_pub(name)

    def generate_priv(self,name):
        file_name = '{}_privRSA.pem'.format(name)
        self.priv_file = file_name
        priv_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        pem = priv_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        with open('chaves/{}'.format(file_name), 'wb') as f:
            f.write(pem)
        f.close()
        self.priv_key = priv_key
        
    def generate_pub(self, name):
        file_name = '{}_pubRSA.pem'.format(name)
        self.pub_file = file_name
        pub_key = self.priv_key.public_key()
        print(str(pub_key))
        pem = pub_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        with open('chaves/{}'.format(file_name), 'wb') as f:
            f.write(pem)
        f.close() 
        self.pub_key = pem.decode()

    def read_priv(self,priv_file):
        priv_key = open('chaves/{}'.format(priv_file)).read()
        return priv_key

    def load_priv(self, key):
        priv_key = serialization.load_pem_private_key(
            bytes(key),
            password=None,
            backend=default_backend()
        )
        return priv_key

    def read_pub(self, pub_file):        
        pub_key = open('chaves/{}'.format(pub_file)).read()
        return pub_key

    def load_pub(self,key):
        pub_key = serialization.load_pem_public_key(
            key.encode(),
            backend=default_backend()
        )
        return pub_key

    def sign_message(self, message):
        prehashed_msg = hashlib.sha256(message.encode()).digest()
        signature = self.priv_key.sign(prehashed_msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return signature

    def verify_sig(self,signature,pub_key,message):
        prehashed_msg = hashlib.sha256(message.encode()).digest()
        try:
            pub_key.verify(signature,
                    prehashed_msg,
                    ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except InvalidSignature:
            return False
