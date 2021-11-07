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
import sys
import urllib.request

class ClientDetails:
    def __init__(self, UId, Key, parameters) -> None:
        self.UId = UId
        self.Key = Key
        self.parameters = parameters

def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data

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
        print(f"Client - {address} : Connected")
        while True:
            try:
                data = recvall(client)
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
    
    def handle_connection(self, packetJson):
        packet = packetJson["Data"]
        try:
            sessionId = packetJson["SessionId"]
            symmetric_key = self.SessionUidLookUps[sessionId].Key
            nonce = self.SessionUidLookUps[sessionId].UId
            serialDecrypted = Crypt.SymmetricCrypto.Decrypt(nonce, packet, symmetric_key)
            packet = pickle.loads(serialDecrypted)
        except Exception as e:
            decrypted = Crypt.RSACryptography.DecryptMessage(packet, self.private_key)
            packet = pickle.loads(decrypted)

        if(packet.ReqType == Tor.TorActions.EstablishSymKey):
            decryptId = os.urandom(16)
            decrypted_payload = packet.Payload
            client_pubkey_serial = decrypted_payload["GenPublicKey"]
            client_pubkey = serialization.load_pem_public_key(
                        client_pubkey_serial,
                        backend=default_backend()
                    )
            parameters = dh.generate_parameters(generator=decrypted_payload["Key_Generator"], key_size=decrypted_payload["Key_length"], backend=default_backend())
            #self.SessionUidLookUps[packet.SessionId] = decryptId
            private_key = parameters.generate_private_key()
            my_public_key = private_key.public_key()
            #shared_key = private_key.exchange(client_pubkey)
            # derived_key = HKDF(
            #         algorithm=hashes.SHA256(),
            #         length=32,
            #         salt=None,
            #         info=b'handshake data',
            #         backend=default_backend()
            #     ).derive(shared_key)
            derived_key = b"h"*32
            pem = my_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.SessionUidLookUps[packet.SessionId] = ClientDetails(decryptId, derived_key, parameters)
            #encryptedData = Crypt.SymmetricCrypto.Encrypt(decryptId, b"Test", derived_key)
            packet = Tor.TorPacket(None, None, packet.SessionId)
            packet.Payload = {"PublicKey" : pem, "UId" : decryptId, "Test" : derived_key}
            return pickle.dumps(packet)
        
        
        elif(packet.ReqType == Tor.TorActions.Forward):
            symmetric_key = self.SessionUidLookUps[packet.SessionId].Key
            nonce = self.SessionUidLookUps[packet.SessionId].UId
            serial_payload = pickle.dumps({"Data" : packet.Payload, "SessionId" : packet.SessionId})
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward:
                    HOST = packet.Dst
                    PORT = int(packet.DstPort)
                    forward.connect((HOST, PORT))
                    forward.sendall(serial_payload)
                    dataRecv = recvall(forward)
                encrypted_data = Crypt.SymmetricCrypto.Encrypt(nonce, dataRecv, symmetric_key)
                return encrypted_data
            except Exception as e:
                print(e)
                return str(e)

        elif(packet.ReqType == Tor.TorActions.Browse):
            try:
                # open a connection to a URL using urllib
                url = packet.Payload["url"]
                webUrl  = urllib.request.urlopen(url)

                #get the result code and print it
                print (f"url : {url} - result code: {str(webUrl.getcode())}")
                symmetric_key = self.SessionUidLookUps[packet.SessionId].Key
                nonce = self.SessionUidLookUps[packet.SessionId].UId
                # read the data from the URL and print it
                dataRecv = webUrl.read()
                encrypted_data = Crypt.SymmetricCrypto.Encrypt(nonce, dataRecv, symmetric_key)
                return dataRecv
            except Exception as e:
                print(e)
                return str(e)
            


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = TorServer(port)
    server.StartListening()
