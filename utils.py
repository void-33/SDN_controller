from ofproto.header import OFPHeader
from ofproto.switch_features import OFPSwitchFeaturesBody
from ofproto.constants import OF_VERSION_1_3, OFPT
import struct


def safe_recv(connection, size):
    # ensures we receive exactly "size" bytes
    blocks = []
    recieved = 0

    # this is done because sometimes not all 8 bytes may have arrived at the socket buffer
    while recieved < size:
        block = connection.recv(size - recieved)
        if not block:
            # connection closed by the switch
            return None
        blocks.append(block)
        recieved += len(block)

    # join blocks with b'' which is an empty byte string
    return b"".join(blocks)


def extract_header(connection):
    header_raw = safe_recv(connection, OFPHeader.STRUCT_SIZE)

    if not header_raw:
        return None

    header = OFPHeader.parse(header_raw)

    return header


def extract_body(connection,message_length:int):
    body_data = b""
    if message_length > OFPHeader.STRUCT_SIZE:
        body_data = safe_recv(connection, message_length - 8)

    return body_data

def send_hello(connection,xid:int):
    header = OFPHeader(OF_VERSION_1_3, OFPT.HELLO,OFPHeader.STRUCT_SIZE, xid)
    connection.sendall(header.pack())

def send_feature_request(connection, xid:int):
    header = OFPHeader(OF_VERSION_1_3, OFPT.FEATURES_REQUEST, OFPHeader.STRUCT_SIZE,xid)
    connection.sendall(header.pack())

def send_echo_reply(connection, xid:int):
    header = OFPHeader(OF_VERSION_1_3, OFPT.ECHO_REPLY, OFPHeader.STRUCT_SIZE, xid)
    connection.sendall(header.pack())

def unpack_dpid(body_data:bytes):
    features_reply_body = OFPSwitchFeaturesBody.parse(body_data)
    return features_reply_body.datapath_id

def unpack_match_length(data:bytes):
    """
    unpack the match length from the first 4 bytes of match struct
    """
    return struct.unpack('!HH',data[:4])[1]


def extract_in_port(oxm_field,oxm_end):
    oxm_ptr = 0

    while oxm_ptr < oxm_end:
        # Read OXM header
        oxm_class,field_and_mask,oxm_length = struct.unpack('!HBB',oxm_field[oxm_ptr:oxm_ptr+4])

        field = field_and_mask >> 1

        value_offset = oxm_ptr + 4
        value = oxm_field[value_offset:value_offset + oxm_length]

        # Check for IN_PORT
        if oxm_class == 0x8000 and field == 0:
            in_port = struct.unpack('!I',value)[0]
            return in_port

        # Move to next OXM
        oxm_ptr += 4 + oxm_length

    return None

