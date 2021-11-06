from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import socket
import threading

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    def listen(self):
        print("Listening for connections")
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
                    # Set the response to echo back the recieved data 
                    peer_public_key = serialization.load_pem_public_key(
                        data,
                        backend=default_backend()
                    )
                    # Generate some parameters. These can be reused.
                    
                    # Generate a private key for use in the exchange.
                    private_key = self.parameters.generate_private_key()
                    my_public_key = private_key.public_key()
                    shared_key = private_key.exchange(peer_public_key)
                    pem = my_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    client.send(pem)
                    serialization.load_pem_public_key(
                        shared_key,
                        backend=default_backend()
                    )
                else:
                    raise Exception('Client disconnected')
            except Exception as e:
                raise e
                client.close()
                return False

if __name__ == "__main__":
    while True:
        port_num = 65432#input("Port? ")
        try:
            port_num = int(port_num)
            break
        except ValueError:
            pass

    ThreadedServer('',port_num).listen()