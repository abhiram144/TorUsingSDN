from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import socket
import uuid



HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # Generate some parameters. These can be reused.
    # Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()
    # In a real handshake the peer_public_key will be received from the
    # other party. For this example we'll generate another private key and
    # get a public key from that. Note that in a DH handshake both peers
    # must agree on a common set of parameters.
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    s.sendall(pem) 
    data = s.recv(1024)#parameters.generate_private_key().public_key()
    server_public_key = serialization.load_pem_public_key(
                        data,
                        backend=default_backend()
                    )
    shared_key = private_key.exchange(server_public_key)
    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
print(derived_key)