import socket
import _thread
import struct
from ofproto.header import OFPHeader
from ofproto.switch_features import OFPSwitchFeaturesBody
from ofproto.packet_in import OFPPacketIn
from ofproto.match import OFPMatch
from ofproto.constants import OF_VERSION_1_3, OFPT,OFPP, OFPFC, OFPMT, OFP
from utils import *


# OpenFlow 1.3 PACKET_OUT Fixed Body: !IIH6x
# ! = Big-Endian
# I = uint32_t (4 bytes) -> buffer_id
# I = uint32_t (4 bytes) -> in_port
# H = uint16_t (2 bytes) -> actions_len
# 6x = padding (6 bytes) -> pad[6]
# Total = 16 bytes (plus 8 bytes header = 24 bytes)


switches = {}  # dpid -> connection
mac_to_port = {}    # dpid -> {mac:port}


def send_table_miss_flow(connection):
    # OFPT_FLOW_MOD (14)
    # This programs the switch to send unmatched packets to the controller
    
    # 1. Header (8 bytes)
    # Type 14, Length 56 (for a basic empty match FlowMod)
    header = struct.pack('!BBHI', OF_VERSION_1_3, 14, 56, 1)
    
    # 2. Flow Mod Fixed Part (40 bytes)
    cookie = 0
    cookie_mask = 0
    table_id = 0
    command = 0 # OFPFC_ADD
    idle_timeout = 0
    hard_timeout = 0
    priority = 0 # Lowest priority
    buffer_id = 0xffffffff # OFP_NO_BUFFER
    out_port = 0xffffffff # OFPP_ANY
    out_group = 0xffffffff # OFPG_ANY
    flags = 0
    
    flow_mod_fixed = struct.pack('!QQBBHHHIIIH2x', 
        cookie, cookie_mask, table_id, command, 
        idle_timeout, hard_timeout, priority, 
        buffer_id, out_port, out_group, flags)

    # 3. Empty Match (8 bytes)
    # type=1 (OFPMT_OXM), length=4 (no fields) + 4 bytes padding
    match = struct.pack('!HH4x', 1, 4)
    
    # 4. Instruction: Apply Actions -> Output to Controller
    # instruction_type=4 (OFPIT_APPLY_ACTIONS), len=24
    # action_type=0 (OFPAT_OUTPUT), len=16, port=0xfffffffd (CONTROLLER), max_len=0xffff
    instruction = struct.pack('!HH4x', 4, 24) # OFPIT_APPLY_ACTIONS
    action = struct.pack('!HHIH6x', 0, 16, 0xfffffffd, 0xffff)
    
    # Total message = header(8) + flow_mod_fixed(40) + match(8) + instruction(8) + action(16)
    # Wait, 8+40+8+8+16 = 80 bytes. Let's fix the header length:
    header = struct.pack('!BBHI', OF_VERSION_1_3, 14, 80, 1)
    
    connection.sendall(header + flow_mod_fixed + match + instruction + action)
    # print("Sent Table-Miss flow entry to Switch")


def install_mac_flow(connection, dst_mac, out_port, xid):
    # FlowMod to forward packets to known destination MAC
    # Header
    header_len = 80
    header = struct.pack('!BBHI', OF_VERSION_1_3, OFPT.FLOW_MOD, header_len, xid)
    # FlowMod fixed part
    flow_mod_fixed = struct.pack('!QQBBHHHIIIH2x',
        0, 0, 0, OFPFC.ADD, 0, 0, 100, OFP.NO_BUFFER, 0xffffffff, 0xffffffff, 0)
    # Match: destination MAC
    # OXM: class=0x8000 (OpenFlow basic), field=3 (eth_dst), no mask, length=6
    match = struct.pack('!HH', OFPMT.OXM, 12) + struct.pack('!HBB6s2x', 0x8000, 6<<1, 6, dst_mac)  # padded to 8 bytes
    # Instruction + action
    instruction = struct.pack('!HH4x', 4, 24)  # OFPIT_APPLY_ACTIONS
    action = struct.pack('!HHIH6x', 0, 16, out_port, 0)  # output to port
    connection.sendall(header + flow_mod_fixed + match + instruction + action)
    print(f"Installed flow for dst MAC {':'.join(f'{b:02x}' for b in dst_mac)} -> port {out_port}")

def handle_switch(connection, address):
    print(f"New connection from {address}")
    formatted_dpid = None

    #receive data from switch
    while True:
        try:
            header = extract_header(connection)
            if header is None:
                break

            #read remaining bytes after header
            body_data = extract_body(connection, header.message_length)

            #Process further based on the TYPE in header
            if header.message_type == OFPT.HELLO:
                send_hello(connection, header.xid)
                send_feature_request(connection, header.xid + 1)

            elif header.message_type == OFPT.ECHO_REQUEST:
                send_echo_reply(connection, header.xid)

            elif header.message_type == OFPT.FEATURES_REPLY:
                dpid = unpack_dpid(body_data)

                #convert it to hex string 00:00:00:00
                dpid_hex = f"{dpid:016x}"
                formatted_dpid = ":".join(dpid_hex[i:i+2] for i in range(0,16,2))

                switches[formatted_dpid] = connection

                # Initialize MAC table for this switch
                if formatted_dpid not in mac_to_port:
                    mac_to_port[formatted_dpid] = {}

                print(f"Handshake Complete! Registered Switch DPID: {formatted_dpid} for {address}")

                send_table_miss_flow(connection)

            elif header.message_type == OFPT.PACKET_IN:
                if not formatted_dpid:
                    continue

                #unpack the body
                packet_in_body = OFPPacketIn.parse(body_data)
                match_len = packet_in_body.ofp_match.length
                oxm_length = match_len - 4
                
                # 2. Extract In_Port & Ethernet Frame
                ethernet_frame = packet_in_body.frame_data
                in_port = extract_in_port(packet_in_body.ofp_match.oxm_field,oxm_length)
                if in_port is None: in_port = OFPP.CONTROLLER

                # 3. MAC Learning
                src_mac = ethernet_frame[6:12]
                dst_mac = ethernet_frame[0:6]
                mac_to_port[formatted_dpid][src_mac] = in_port

                # 4. Determine Output Port
                out_port = mac_to_port[formatted_dpid].get(dst_mac, OFPP.FLOOD)

                # 5. Install Flow (FlowMod) if we know where the destination is
                if out_port != OFPP.FLOOD:
                    # Match: 0x8000 (Basic) | 0x06 (Eth_Dst) | Len 6
                    # 12 byte match + 4 byte padding = 16
                    match_packet = struct.pack('!HHHBB6s2x', 1, 12, 0x8000, 6<<1, 6, dst_mac)
                    
                    # Action: Output to port (16 bytes)
                    action_fm = struct.pack('!HHIH6x', 0, 16, out_port, 0xffff)
                    # Instruction: Apply Actions (8 bytes)
                    inst_fm = struct.pack('!HH4x', 4, 24)
                    
                    # FlowMod Fixed (40 bytes) - Priority 100, Idle Timeout 30s
                    fm_fixed = struct.pack('!QQBBHHHIIIH2x', 0, 0, 0, 0, 30, 0, 100, 0xffffffff, 0xffffffff, 0xffffffff, 0)
                    
                    fm_header = struct.pack('!BBHI', 4, 14, 8 + 40 + 16 + 24, header.xid)
                    connection.sendall(fm_header + fm_fixed + match_packet + inst_fm + action_fm)
                    print(f"[{formatted_dpid}] Flow Installed: {dst_mac.hex(':')} -> Port {out_port}")

                # 6. Send Packet Out (To actually deliver this first packet)
                # Action: Output (16 bytes)
                po_action = struct.pack('!HHIH6x', 0, 16, out_port, 0xffff)
                
                po_body_len = 16 + 16 # Fixed Body + 1 Action
                if packet_in_body.buffer_id== 0xffffffff:
                    po_body_len += len(ethernet_frame)
                
                po_header = struct.pack('!BBHI', 4, 13, 8 + po_body_len, header.xid)
                po_fixed = struct.pack('!IIH6x', packet_in_body.buffer_id, in_port, 16)
                
                packet_out_msg = po_header + po_fixed + po_action
                if packet_in_body.buffer_id == 0xffffffff:
                    packet_out_msg += ethernet_frame
                
                connection.sendall(packet_out_msg)
                
                # Console Log
                d_mac_str = dst_mac.hex(':')
                s_mac_str = src_mac.hex(':')
                # print(f"[{formatted_dpid}] {s_mac_str} -> {d_mac_str} | Port: {out_port}")
        except Exception as e:
            print(f"Error with {address}:{e}")
            break
    
    connection.close()
    print(f"Switch {address} disconnected")



if __name__ == '__main__':
    #localhost
    HOST = '127.0.0.1'
    #default port in mininet for controller to listen to
    PORT = 6653

    #create a TCP socket
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    # Add this line BEFORE bind
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_details = (HOST,PORT)

    print(f"Starting server on port:{PORT}")

    #bind the socket to the defined port
    server_socket.bind(server_details)

    #listen for incoming connections
    server_socket.listen()

    print(f"Controller listening on {HOST}:{PORT}")

    while True:
        connection, client = server_socket.accept()
        # #new instance for new thread
        _thread.start_new_thread(handle_switch,(connection,client))

