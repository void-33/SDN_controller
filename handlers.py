import utils
import ofproto.constants as ofc
from ofproto.packet_in import OFPPacketIn
from ofproto.multipart import OFPMultipartReply
from ofproto.lldp import LLDPPacket, ETHERTYPE_LLDP
import topology
import struct
import threading

# Industry standard LLDP probe interval (ONOS / ODL / Ryu all default to 5s)
LLDP_INTERVAL = 5  # seconds

switches    = {}  # dpid -> connection
mac_to_port = {}  # dpid -> {mac:port}
# Accumulate ports across multiple MULTIPART_REPLY messages (has_more flag)
_pending_ports = {}  # dpid -> [port_no, ...]


def start_lldp_sender():
    """
    Spawns a single daemon thread that periodically floods LLDP frames
    out of every known port on every connected switch.
    Called once at controller startup from controller.py.
    """
    t = threading.Thread(target=_lldp_sender_loop, daemon=True, name="lldp-sender")
    t.start()
    print(f"[LLDP] Periodic sender started (interval={LLDP_INTERVAL}s)")


def _lldp_sender_loop():
    """
    Background loop: every LLDP_INTERVAL seconds, iterate over every
    registered switch and send one LLDP PACKET_OUT per port.
    Prints topology on initial discovery and whenever it changes.
    """
    stop = threading.Event()
    prev_links = set()
    topology_printed = False
    
    while not stop.wait(LLDP_INTERVAL):
        for dpid, connection in list(switches.items()):
            port_nos = topology.get_ports(dpid)
            if not port_nos:
                continue

            dpid_int = int(dpid.replace(':', ''), 16)
            for port_no in port_nos:
                try:
                    utils.send_lldp_out(connection, dpid_int, port_no, xid=0)
                except Exception:
                    # Switch may have disconnected between iterations
                    pass

        current_links = set(topology.get_all_links())
        
        # Print topology on first discovery (when prev_links is empty) or when it changes
        if current_links and (not prev_links or current_links != prev_links):
            topology.print_topology()
            prev_links = current_links


def handle_switch_connection(connection, address):
    print(f"New connection from {address}")
    formatted_dpid = None

    # receive data from switch
    while True:
        try:
            header = utils.extract_header(connection)
            if header is None:
                break

            # read remaining bytes after header
            body_data = utils.extract_body(connection, header.message_length)

            # Process further based on the TYPE in header
            if header.message_type == ofc.OFPT.HELLO:
                utils.send_hello(connection, header.xid)
                utils.send_feature_request(connection, header.xid + 1)

            elif header.message_type == ofc.OFPT.ECHO_REQUEST:
                utils.send_echo_reply(connection, header.xid)

            elif header.message_type == ofc.OFPT.FEATURES_REPLY:
                formatted_dpid = handle_features_reply(
                    connection=connection,
                    body_data=body_data,
                    address=address,
                    switches=switches,
                    mac_to_port=mac_to_port,
                    xid=header.xid,
                )

            elif header.message_type == ofc.OFPT.MULTIPART_REPLY:
                if formatted_dpid:
                    handle_multipart_reply(
                        body_data=body_data,
                        formatted_dpid=formatted_dpid,
                        connection=connection,
                        xid=header.xid,
                    )

            elif header.message_type == ofc.OFPT.PACKET_IN:
                if not formatted_dpid:
                    continue

                handle_packet_in(
                    connection=connection,
                    body_data=body_data,
                    formatted_dpid=formatted_dpid,
                    mac_to_port=mac_to_port,
                    xid=header.xid,
                )

        except Exception as e:
            print(f"Error with {address}:{e}")
            break

    connection.close()
    # Clean up so the LLDP sender doesn't try to use the stale socket
    utils.release_send_lock(connection)
    if formatted_dpid and switches.get(formatted_dpid) is connection:
        switches.pop(formatted_dpid, None)
        topology.deregister_switch(formatted_dpid)
    print(f"Switch {address} disconnected")

def handle_features_reply(connection, body_data, address, switches, mac_to_port, xid):
    dpid = utils.unpack_dpid(body_data)

    # convert it to hex string 00:00:00:00
    dpid_hex = f"{dpid:016x}"
    formatted_dpid = ":".join(dpid_hex[i : i + 2] for i in range(0, 16, 2))

    switches[formatted_dpid] = connection

    # Initialize MAC table for this switch
    if formatted_dpid not in mac_to_port:
        mac_to_port[formatted_dpid] = {}

    print(f"Handshake Complete! Registered Switch DPID: {formatted_dpid} for {address}")

    utils.send_table_miss_flow(connection)
    utils.send_port_desc_request(connection, xid=2)

    return formatted_dpid


def handle_multipart_reply(body_data, formatted_dpid, connection, xid):
    """
    Parse PORT_DESC reply and send LLDP out of every physical port.
    Accumulates port data across multiple replies (has_more flag).
    """
    reply = OFPMultipartReply.parse(body_data)

    # Accumulate ports in case the reply is split across multiple messages
    if formatted_dpid not in _pending_ports:
        _pending_ports[formatted_dpid] = []

    for port in reply.ports:
        # Skip reserved OpenFlow ports (port_no >= 0xFFFFFF00)
        if port.port_no < 0xFFFFFF00:
            _pending_ports[formatted_dpid].append(port.port_no)

    # Only finalise once we have received all reply fragments
    if not reply.has_more:
        port_nos = _pending_ports.pop(formatted_dpid, [])
        topology.register_ports(formatted_dpid, port_nos)
        print(f"[{formatted_dpid}] Ports discovered: {sorted(port_nos)}")

        # Convert formatted_dpid back to int so LLDPPacket can build src MAC
        dpid_int = int(formatted_dpid.replace(':', ''), 16)
        for port_no in port_nos:
            utils.send_lldp_out(connection, dpid_int, port_no, xid)


def handle_packet_in(connection, body_data,formatted_dpid, mac_to_port,xid):
    # unpack the body
    packet_in_body = OFPPacketIn.parse(body_data)
    match_len = packet_in_body.ofp_match.length
    oxm_length = match_len - 4

    # 2. Extract In_Port & Ethernet Frame
    ethernet_frame = packet_in_body.frame_data
    in_port = utils.extract_in_port(
        packet_in_body.ofp_match.oxm_field, oxm_length
    )

    # 2a. Check if this is an LLDP packet - handle separately
    if len(ethernet_frame) >= 14:
        ethertype = struct.unpack('!H', ethernet_frame[12:14])[0]
        if ethertype == ETHERTYPE_LLDP:
            lldp_pkt = LLDPPacket.parse(ethernet_frame)
            if lldp_pkt:
                src_mac = lldp_pkt.get_chassis_mac()
                src_port = lldp_pkt.get_port_number()
                if src_mac and src_port is not None and in_port is not None:
                    # Find the sender's dpid from the chassis MAC
                    src_dpid = ':'.join(f'{b:02x}' for b in src_mac)
                    src_dpid = '00:00:' + src_dpid  # pad to full 8-byte dpid format
                    topology.add_link(src_dpid, src_port, formatted_dpid, in_port)
                    # print(f"[Topology] Link: {src_dpid}:{src_port} --> {formatted_dpid}:{in_port}")
            return  # Do not flood or learn MAC from LLDP packets
    if in_port is None:
        in_port = ofc.OFPP.CONTROLLER

    # 3. MAC Learning
    src_mac = ethernet_frame[6:12]
    dst_mac = ethernet_frame[0:6]
    mac_to_port[formatted_dpid][src_mac] = in_port

    # 4. Determine Output Port
    out_port = mac_to_port[formatted_dpid].get(dst_mac, ofc.OFPP.FLOOD)

    # 5. Install Flow (FlowMod) if we know where the destination is
    if out_port != ofc.OFPP.FLOOD:
        utils.install_mac_flow(
            connection=connection,
            dst_mac=dst_mac,
            out_port=out_port,
            xid=xid,
        )

    # send actual packet now
    utils.send_packet_out(
        connection=connection,
        packet_in_body=packet_in_body,
        in_port=in_port,
        out_port=out_port,
        ethernet_frame=ethernet_frame,
        xid=xid,
    )
