from enum import IntEnum

OF_VERSION_1_3 = 0x04

class OFPT(IntEnum):
    HELLO = 0
    ERROR = 1
    ECHO_REQUEST = 2
    ECHO_REPLY = 3
    EXPERIMENTER = 4
    FEATURES_REQUEST = 5
    FEATURES_REPLY = 6
    PACKET_IN = 10
    PACKET_OUT = 13
    FLOW_MOD = 14
    MULTIPART_REQUEST = 18
    MULTIPART_REPLY = 19


class OFPP(IntEnum):
    FLOOD = 0xFFFFFFFB
    CONTROLLER = 0xFFFFFFFD
    ANY = 0xFFFFFFFF

class OFPG(IntEnum):
    ANY = 0xFFFFFFFF

class OFP(IntEnum):
    NO_BUFFER = 0xFFFFFFFF

class OFPFC(IntEnum):
    ADD = 0
    MODIFY = 1
    DELETE = 2

class OFPMT(IntEnum):
    OXM = 1

class OFPAT(IntEnum):
    OUTPUT = 0

class OFPIT(IntEnum):
    APPLY_ACTIONS = 4

class OFPMP(IntEnum):
    PORT_DESC = 13