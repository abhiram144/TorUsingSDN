import enum
import CryptoHelper as helper
import json
import socket
import TorHelper as Tor
import pickle
import CryptoHelper as Crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import xml.etree.ElementTree as ET
keyGenerator = 2
Sym_KeyLen = 512
class Relays:
    def __init__(self) -> None:
        self.public_key = None
        self.ip = None
        self.port = None
        self.SymmKey = None
        self.PublicKey = None
        self.UId = None
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

class TorSession:
    def __init__(self):
        hostname = socket. gethostname()
        IPAddr = socket. gethostbyname(hostname)
        self.IPAddr = IPAddr
        self.SessionId = uuid.uuid4()
        self.Relays = []
        self.parameters = dh.generate_parameters(generator=keyGenerator, key_size=Sym_KeyLen, backend=default_backend())
        self.Rsa = Crypto.RSACryptography().InitializeRSA()
        self.PickNodesAndEstablishKeys()

    def PrepareForwardingPacket(self, relays, message, action):
        #if symm key is not established yet ........ encrypt with public Key
        packet = Tor.TorPacket(None, None, self.SessionId, reqType=action)
        packet.Payload = message
        #Encrypt with public key if symmetric key is not established
        serialized_packet = pickle.dumps(packet)
        if(relays[-1].SymmKey == None):
            #packet.Payload = message
            packet = helper.RSACryptography.EncryptMessage(serialized_packet, relays[-1].PublicKey)
        else:
            #packet.Payload = message
            packet = helper.SymmetricCrypto.Encrypt(relays[-1].UId, serialized_packet, relays[-1].SymmKey)
        for i in range(1, len(relays)):
            nextRelay = relays[len(relays) - i]
            currentRelay = relays[len(relays) - i - 1]
            newLayer = Tor.TorPacket(currentRelay.ip, currentRelay.port, self.SessionId, reqType=Tor.TorActions.Forward)
            newLayer.Dst = nextRelay.ip
            newLayer.DstPort = nextRelay.port
            #cipher = Cipher(algorithms.AES(currentRelay.SymmKey), modes.CBC(currentRelay.UId), backend=default_backend())
            #encryptor = cipher.encryptor()
            #ct = Crypto.SymmetricCrypto.Encrypt(currentRelay.UId, serialized_packet, currentRelay.SymmKey)
            newLayer.Payload = packet
            serialized_packet = pickle.dumps(newLayer)
            packet = Crypto.SymmetricCrypto.Encrypt(currentRelay.UId, serialized_packet, currentRelay.SymmKey)
        return packet
        
        

    
    def EstablishKeys(self, relayList):
        # returns JSON object as
        # a dictionary
        currentRelayNodes = []
        for i, relay in enumerate(relayList):
            currentRelayNodes.append(relay)
            #relay.Uid = os.urandom(16)
            dh_private_key = Crypto.SymmetricCrypto.GeneratePrivateKey(self.parameters)
            dh_public_key_serial = Crypto.RSACryptography.SerializePublicKey(dh_private_key.public_key())

            
            message = { "GenPublicKey" : dh_public_key_serial, "Key_Generator" : keyGenerator, "Key_length" : Sym_KeyLen}
            preparedPacket = self.PrepareForwardingPacket(currentRelayNodes, message, Tor.TorActions.EstablishSymKey)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                HOST = relayList[0].ip
                PORT = int(relayList[0].port)
                s.connect((HOST, PORT))
                s.sendall(pickle.dumps({"Data" : preparedPacket, "SessionId" : self.SessionId}))
                dataRecv = recvall(s)
                if not dataRecv:
                    raise Exception("Error establishing Symmetric Keys")
                if(i > 0):
                    dataRecv = Crypto.SymmetricCrypto.Decrypt(relayList[0].UId, dataRecv, relayList[0].SymmKey)
                packet = pickle.loads(dataRecv)
            server_pub_key_Serial = packet.Payload["PublicKey"]
            server_pub_key = serialization.load_pem_public_key(
                    server_pub_key_Serial,
                    backend=default_backend()
                )
            #shared_key = dh_private_key.exchange(server_pub_key)
            ## Perform key derivation.
            # derived_key = HKDF(
            #     algorithm=hashes.SHA256(),
            #     length=32,
            #     salt=None,
            #     info=b'handshake data',
            #     backend=default_backend()
            # ).derive(shared_key)

            derived_key = packet.Payload["Test"]

            relay.SymmKey = derived_key
            relay.UId = packet.Payload["UId"]#Crypto.SymmetricCrypto.Decrypt(packet.Payload["UId"], packet.Payload["Test"], relay.SymmKey)
            

    

    def PickNodesAndEstablishKeys(self):
        # Opening JSON file
        tree = ET.parse('Config copy.xml')
        root = tree.getroot()
        relayList = []
        for relay in root.iter('relays'):
            node = Relays()
            node.ip = relay.find("ip").text
            node.port = relay.find("port").text
            public_key = relay.find("Public_key").text
            node.PublicKey = serialization.load_pem_public_key(
                                public_key.encode(),
                                backend=default_backend()
                            )
            relayList.append(node)
        if(len(relayList) <= 0):
            print("Error in getting relay Nodes")
            exit(0)
        self.Relays = relayList
        self.EstablishKeys(relayList)
    
    def Browse(self, url):
        message = {"url" : url}
        preparedPacket = self.PrepareForwardingPacket(self.Relays, message, Tor.TorActions.Browse)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            HOST = self.Relays[0].ip
            PORT = int(self.Relays[0].port)
            s.connect((HOST, PORT))
            s.sendall(pickle.dumps({"Data" : preparedPacket, "SessionId" : self.SessionId}))
            dataRecv = recvall(s)
            if not dataRecv:
                raise Exception("Error establishing Symmetric Keys")
            for i, relay in self.Relays:
                dataRecv = Crypto.SymmetricCrypto.Decrypt(relay.UId, dataRecv, relay.SymmKey)
        return dataRecv
        

session = TorSession()
while True:
    d1a = input ("Do you want to: \n1) Generate New Identity . \n2) Browse an url  \nQ) Quit: ")
    if d1a == "1":
        session = TorSession()
    elif d1a == "2":
        url = input("Enter Url to browse : ")
        session.Browse(url)
    elif d1a.upper() == "Q":
        break
    else:
        print("Invalid Input")

