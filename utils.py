from ofproto.header import OFPHeader
from ofproto.switch_features import OFPSwitchFeaturesBody
import ofproto.constants as ofc
from ofproto.match import OFPMatch
from ofproto.action_out import OFPActionOut, OFPInstructionActions
from ofproto.packet_out import OFPPacketOut
from ofproto.flow_mod import OFPFlowMod
from ofproto.multipart import OFPMultipartRequest
from ofproto.lldp import LLDPPacket
import struct
import threading

# Per-connection send lock.
# Python's socket.sendall() releases the GIL during I/O syscalls, so bytes
# from two concurrent sendall() calls on the same socket can interleave,
# corrupting the OpenFlow message stream and causing the switch to send TCP RST.
# This dict maps each connection socket to its own lock.
_socket_locks: dict = {}
_socket_locks_guard = threading.Lock()


def locked_send(connection, data: bytes):
    """Thread-safe wrapper around sendall. Always use this instead of connection.sendall()."""
    with _socket_locks_guard:
        if connection not in _socket_locks:
            _socket_locks[connection] = threading.Lock()
        lock = _socket_locks[connection]
    with lock:
        connection.sendall(data)


def release_send_lock(connection):
    """Call when a connection is closed to free its lock entry."""
    with _socket_locks_guard:
        _socket_locks.pop(connection, None)


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
    header = OFPHeader(ofc.OF_VERSION_1_3, ofc.OFPT.HELLO,OFPHeader.STRUCT_SIZE, xid)
    locked_send(connection, header.pack())

def send_feature_request(connection, xid:int):
    header = OFPHeader(ofc.OF_VERSION_1_3, ofc.OFPT.FEATURES_REQUEST, OFPHeader.STRUCT_SIZE,xid)
    locked_send(connection, header.pack())

def send_echo_reply(connection, xid:int):
    header = OFPHeader(ofc.OF_VERSION_1_3, ofc.OFPT.ECHO_REPLY, OFPHeader.STRUCT_SIZE, xid)
    locked_send(connection, header.pack())

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


def send_table_miss_flow(connection):
    # This programs the switch to send unmatched packets to the controller

    message_length = 8 + 48 + 8 + 16

    header_to_send = OFPHeader(
        version=ofc.OF_VERSION_1_3,
        message_type=ofc.OFPT.FLOW_MOD,
        message_length=message_length,
        xid=1,
    )
    header_data = header_to_send.pack()

    match_to_send = OFPMatch(type=ofc.OFPMT.OXM, length=4, oxm_field=b'')

    flow_mod_to_send = OFPFlowMod(
        cookie=0,
        cookie_mask=0,
        table_id=0,
        command=0,
        idle_timeout=0,
        hard_timeout=0,
        priority=0,
        buffer_id=ofc.OFP.NO_BUFFER,
        out_port=ofc.OFPP.ANY,
        out_group=ofc.OFPG.ANY,
        flags=0,
        match=match_to_send
    )
    flow_mod_data = flow_mod_to_send.pack()

    inst_to_send = OFPInstructionActions(type=ofc.OFPIT.APPLY_ACTIONS, len=24)
    inst_data = inst_to_send.pack()
    action_to_send = OFPActionOut(type=ofc.OFPAT.OUTPUT, len=16, port=ofc.OFPP.CONTROLLER, max_len=0xffff)
    action_data = action_to_send.pack()

    locked_send(connection, header_data + flow_mod_data + inst_data + action_data)


def install_mac_flow(connection, dst_mac, out_port, xid):
    oxm_field = struct.pack("!HBB6s", 0x8000, 3 << 1, 6, dst_mac)
    match_to_send = OFPMatch(type=ofc.OFPMT.OXM, length=14, oxm_field=oxm_field)

    action_to_send = OFPActionOut(
        type=ofc.OFPAT.OUTPUT, len=16, port=out_port, max_len=0xFFFF
    )
    action_data = action_to_send.pack()

    inst_to_send = OFPInstructionActions(
        type=ofc.OFPIT.APPLY_ACTIONS, len=24
    )
    inst_data = inst_to_send.pack()

    # FlowMod Fixed (40 bytes) - Priority 100, Idle Timeout 30s
    flow_mod_to_send = OFPFlowMod(
        cookie=0,
        cookie_mask=0,
        table_id=0,
        command=ofc.OFPFC.ADD,
        idle_timeout=30,
        hard_timeout=0,
        priority=100,
        buffer_id=ofc.OFP.NO_BUFFER,
        out_port= ofc.OFPP.ANY,
        out_group=ofc.OFPG.ANY,
        flags=0,
        match=match_to_send,
    )
    flow_mod_data = flow_mod_to_send.pack()

    message_length = 8 + 56 + 24  # instr len includes action data too
    header_to_send = OFPHeader(
        version=ofc.OF_VERSION_1_3,
        message_type=ofc.OFPT.FLOW_MOD,
        message_length=message_length,
        xid=xid,
    )
    header_data = header_to_send.pack()
    locked_send(connection, header_data + flow_mod_data + inst_data + action_data)
    # print(
    #     f"[{formatted_dpid}] Flow Installed: {dst_mac.hex(':')} -> Port {out_port}"
    # )

def send_packet_out(connection, packet_in_body,in_port, out_port, ethernet_frame, xid):
    action_to_send = OFPActionOut(
        type=ofc.OFPAT.OUTPUT, len=16, port=out_port, max_len=0xFFFF
    )
    action_data = action_to_send.pack()

    po_body_len = 16 + 16  # Fixed Body + 1 Action
    if packet_in_body.buffer_id == 0xFFFFFFFF:
        po_body_len += len(ethernet_frame)

    message_length = 8 + po_body_len
    header_to_send = OFPHeader(
        version=ofc.OF_VERSION_1_3,
        message_type=ofc.OFPT.PACKET_OUT,
        message_length=message_length,
        xid=xid,
    )
    header_data = header_to_send.pack()

    packet_out_to_send = OFPPacketOut(
        buffer_id=packet_in_body.buffer_id, in_port=in_port, actions_len=16
    )
    packet_out_data = packet_out_to_send.pack()

    packet_out_msg = header_data + packet_out_data + action_data
    if packet_in_body.buffer_id == 0xFFFFFFFF:
        packet_out_msg += ethernet_frame

    locked_send(connection, packet_out_msg)

    # print(f'packet sent, src:{src_mac.hex(':')} -> dst: {dst_mac.hex(':')}')


def send_port_desc_request(connection, xid: int):
    """
    Ask a switch to send back its full port list (OFPMP_PORT_DESC = 13).
    The switch replies with one or more MULTIPART_REPLY messages.
    """
    body = OFPMultipartRequest(type=ofc.OFPMP.PORT_DESC, flags=0).pack()
    header = OFPHeader(
        version=ofc.OF_VERSION_1_3,
        message_type=ofc.OFPT.MULTIPART_REQUEST,
        message_length=OFPHeader.STRUCT_SIZE + len(body),
        xid=xid,
    )
    locked_send(connection, header.pack() + body)


def send_lldp_out(connection, dpid_int: int, port_no: int, xid: int):
    """
    Send an LLDP frame out of a specific port on a switch via PACKET_OUT.
    The switch will forward the raw Ethernet frame out of port_no.
    """
    lldp_frame = LLDPPacket.create(dpid_int, port_no).pack()

    action_to_send = OFPActionOut(
        type=ofc.OFPAT.OUTPUT, len=16, port=port_no, max_len=0xFFFF
    )
    action_data = action_to_send.pack()

    message_length = OFPHeader.STRUCT_SIZE + 16 + len(action_data) + len(lldp_frame)
    header = OFPHeader(
        version=ofc.OF_VERSION_1_3,
        message_type=ofc.OFPT.PACKET_OUT,
        message_length=message_length,
        xid=xid,
    )

    packet_out_to_send = OFPPacketOut(
        buffer_id=ofc.OFP.NO_BUFFER,
        in_port=ofc.OFPP.CONTROLLER,
        actions_len=len(action_data),
    )

    locked_send(
        connection,
        header.pack() + packet_out_to_send.pack() + action_data + lldp_frame
    )

def send_raw_packet_out(connection, ethernet_frame: bytes, out_port: int, xid: int):
    """
    Send a raw Ethernet frame out of a specific port on a switch.
    Used for controlled flooding to remote switches.
    """
    action_to_send = OFPActionOut(
        type=ofc.OFPAT.OUTPUT, len=16, port=out_port, max_len=0xFFFF
    )
    action_data = action_to_send.pack()

    message_length = OFPHeader.STRUCT_SIZE + 16 + len(action_data) + len(ethernet_frame)
    header = OFPHeader(
        version=ofc.OF_VERSION_1_3,
        message_type=ofc.OFPT.PACKET_OUT,
        message_length=message_length,
        xid=xid,
    )

    packet_out_to_send = OFPPacketOut(
        buffer_id=ofc.OFP.NO_BUFFER,
        in_port=ofc.OFPP.CONTROLLER,
        actions_len=len(action_data),
    )

    locked_send(
        connection,
        header.pack() + packet_out_to_send.pack() + action_data + ethernet_frame,
    )