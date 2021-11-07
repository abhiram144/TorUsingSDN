import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
import os

class RSACryptography:
    def InitializeRSA(self, readFromFile = False, storeInFile = False):
        if(not readFromFile):
            private_key = self.GenerateKeys()
        else:
            private_key = self.ReadKeys()
        
        if(storeInFile):
            self.StoreKeysInFiles(private_key)
        return private_key
    
    def GetPrivateKey(self):
        return self.private_key
    
    def GetPublicKey(self):
        return self.public_key

    def GenerateKeys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=512 * 12,
            backend=default_backend()
        )
        # public_key = private_key.public_key()
        # self.public_key, self.private_key = public_key, private_key
        return private_key
    
    def SerializePublicKey(public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def StoreKeysInFiles(self, private_key):
        public_key = private_key.public_key()
        pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key.pem', 'wb') as f:
            f.write(pem)

            
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('public_key.pem', 'wb') as f:
            f.write(pem)
    
    def ReadKeys(self):
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    
    def EncryptMessage(message, public_key):
        if(not isinstance(message, (bytes, bytearray))):
            message = pickle.dumps(message)
        encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return encrypted

    def DecryptMessage(encrypted, private_key):
        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message

class SymmetricCrypto:
    def GeneratePrivateKey(parameters):
        #parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        # Generate a private key for use in the exchange.
        private_key = parameters.generate_private_key()
        return private_key
    


    def Encrypt(nonce, message, symmetric_key):
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()
        return ct
    def Decrypt(nonce, message, symmetric_key):
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        msg = decryptor.update(message) + decryptor.finalize()
        return msg
    


if __name__ == "__main__":
    cryp = RSACryptography()
    private_key = cryp.InitializeRSA(storeInFile=True)
    print("Files are created in current Directory")


