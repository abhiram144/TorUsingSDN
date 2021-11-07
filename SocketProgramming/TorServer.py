from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import CryptoHelper as Crypt
import socket
import threading
import pickle
import TorHelper as Tor
import os

class ClientDetails:
    def __init__(self, UId, Key, parameters) -> None:
        self.UId = UId
        self.Key = Key
        self.parameters = parameters

class TorServer:
    def __init__(self, port):
        print("Initializing Tor Server ....")
        self.cryp = Crypt.RSACryptography()
        self.private_key = self.cryp.InitializeRSA(readFromFile=True)
        self.hostname = socket. gethostname()
        self.IPAddr = socket. gethostbyname(self.hostname)
        self.host = self.IPAddr
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.SessionUidLookUps = {}
        print("Initialization Complete")
        


    def StartListening(self):
        print("Starting Listening for connections")
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        print("Client Connected")
        while True:
            try:
                data = client.recv(size)
                if data:
                    packet = pickle.loads(data)
                    response = self.handle_connection(packet)
                    # Set the response to echo back the recieved data 
                    client.sendall(response)
                else:
                    raise Exception('Client disconnected')
            except Exception as e:
                print(e)
                client.close()
                return False    
    
    def handle_connection(self, packet):
        if(packet.ReqType == Tor.TorActions.EstablishSymKey):
            decryptId = os.urandom(16)
            encData = packet.Payload
            serialDecrypted = Crypt.RSACryptography.DecryptMessage(encData, self.private_key)
            decrypted_payload = pickle.loads(serialDecrypted)
            client_pubkey = decrypted_payload["GenPublicKey"]
            peer_public_key = serialization.load_pem_public_key(
                        client_pubkey,
                        backend=default_backend()
                    )
            parameters = dh.generate_parameters(generator=decrypted_payload["Key_Generator"], key_size=decrypted_payload["Key_length"], backend=default_backend())
            #self.SessionUidLookUps[packet.SessionId] = decryptId
            private_key = parameters.generate_private_key()
            my_public_key = private_key.public_key()
            shared_key = private_key.exchange(peer_public_key)
            derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_key)
            pem = my_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.SessionUidLookUps[packet.SessionId] = ClientDetails(decryptId, derived_key, parameters)
            encryptedData = Crypt.SymmetricCrypto.Encrypt(decryptId, "Test", derived_key)
            packet = Tor.TorPacket(None, None, packet.SessionId)
            packet.Payload = {"PublicKey" : pem, "UId" : decryptId, "Test" : encryptedData}
            return pickle.dumps(packet)
        else:
            pass

if __name__ == "__main__":
    server = TorServer(8081)
    server.StartListening()
