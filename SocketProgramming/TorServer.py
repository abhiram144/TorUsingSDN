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

class TorServer:
    def __init__(self, port):
        print("Initializing Tor Server ....")
        self.cryp = Crypt.RSACryptography()
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
                    self.handle_connection(packet)
                    # Set the response to echo back the recieved data 
                    response = data
                    client.send(response)
                else:
                    raise Exception('Client disconnected')
            except Exception as e:
                print(e)
                client.close()
                return False    
    
    def handle_connection(self, packet):
        if(packet.ReqType == Tor.TorActions.EstablishSymKey):
            decryptId = os.urandom(16)
            decrypted_payload = 
            self.SessionUidLookUps[packet.SessionId] = decryptId

        else:

if __name__ == "__main__":
    server = TorServer(8081)
    server.StartListening()
