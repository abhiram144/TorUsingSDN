from enum import Enum
class TorActions(Enum):
    Forward = 1
    EstablishSymKey = 2
    ReturnPublicKey = 3
    Browse = 4
    NA = 5

class TorPacket:
    def __init__(self, dst, dstPort, SessionId = None, reqType = TorActions.NA):
        self.Dst = dst
        self.DstPort = dstPort
        self.Payload = None
        self.ReqType = reqType
        self.SessionId = SessionId
        self.Uid = None