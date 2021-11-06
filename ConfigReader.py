import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
tree = ET.parse('Config copy.xml')
root = tree.getroot()
for relay in root.iter('relays'):
    dict = {}
    dict["ip"] = relay.find("ip").text
    dict["port"] = relay.find("port").text
    dict["Public_key"] = relay.find("Public_key").text
    peer_public_key = serialization.load_pem_public_key(
                        dict["Public_key"].encode(),
                        backend=default_backend()
                    )
    print("adfadf")