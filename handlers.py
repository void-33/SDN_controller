import utils
import ofproto.constants as ofc
from ofproto.packet_in import OFPPacketIn
from ofproto.multipart import OFPMultipartReply
from ofproto.lldp import LLDPPacket, ETHERTYPE_LLDP
import topology
import struct
import threading

LLDP_INTERVAL = 5

switches    = {}
mac_to_port = {}
_pending_ports = {}


def start_lldp_sender():
    t = threading.Thread(target=_lldp_sender_loop, daemon=True, name="lldp-sender")
    t.start()
    print(f"[LLDP] Periodic sender started (interval={LLDP_INTERVAL}s)")


def _lldp_sender_loop():
    stop = threading.Event()
    prev_links = set()

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
                    pass

        current_links = set(topology.get_all_links())
        if current_links and (not prev_links or current_links != prev_links):
            topology.print_topology()
            prev_links = current_links


def handle_switch_connection(connection, address):
    print(f"New connection from {address}")
    formatted_dpid = None

    while True:
        try:
            header = utils.extract_header(connection)
            if header is None:
                break

            body_data = utils.extract_body(connection, header.message_length)

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
    utils.release_send_lock(connection)
    if formatted_dpid and switches.get(formatted_dpid) is connection:
        switches.pop(formatted_dpid, None)
        topology.deregister_switch(formatted_dpid)
    print(f"Switch {address} disconnected")


def handle_features_reply(connection, body_data, address, switches, mac_to_port, xid):
    dpid = utils.unpack_dpid(body_data)
    dpid_hex = f"{dpid:016x}"
    formatted_dpid = ":".join(dpid_hex[i : i + 2] for i in range(0, 16, 2))

    switches[formatted_dpid] = connection

    if formatted_dpid not in mac_to_port:
        mac_to_port[formatted_dpid] = {}

    print(f"Handshake Complete! Registered Switch DPID: {formatted_dpid} for {address}")

    utils.send_table_miss_flow(connection)
    utils.send_port_desc_request(connection, xid=2)

    return formatted_dpid


def handle_multipart_reply(body_data, formatted_dpid, connection, xid):
    reply = OFPMultipartReply.parse(body_data)

    if formatted_dpid not in _pending_ports:
        _pending_ports[formatted_dpid] = []

    for port in reply.ports:
        if port.port_no < 0xFFFFFF00:
            _pending_ports[formatted_dpid].append(port.port_no)

    if not reply.has_more:
        port_nos = _pending_ports.pop(formatted_dpid, [])
        topology.register_ports(formatted_dpid, port_nos)
        print(f"[{formatted_dpid}] Ports discovered: {sorted(port_nos)}")

        dpid_int = int(formatted_dpid.replace(':', ''), 16)
        for port_no in port_nos:
            utils.send_lldp_out(connection, dpid_int, port_no, xid)


def handle_packet_in(connection, body_data, formatted_dpid, mac_to_port, xid):
    packet_in_body = OFPPacketIn.parse(body_data)
    match_len  = packet_in_body.ofp_match.length
    oxm_length = match_len - 4

    ethernet_frame = packet_in_body.frame_data
    in_port = utils.extract_in_port(packet_in_body.ofp_match.oxm_field, oxm_length)

    # 1. Handle LLDP
    if len(ethernet_frame) >= 14:
        ethertype = struct.unpack('!H', ethernet_frame[12:14])[0]
        if ethertype == ETHERTYPE_LLDP:
            lldp_pkt = LLDPPacket.parse(ethernet_frame)
            if lldp_pkt:
                src_mac  = lldp_pkt.get_chassis_mac()
                src_port = lldp_pkt.get_port_number()
                if src_mac and src_port is not None and in_port is not None:
                    src_dpid = '00:00:' + ':'.join(f'{b:02x}' for b in src_mac)
                    topology.add_link(src_dpid, src_port, formatted_dpid, in_port)
                    topology.add_link(formatted_dpid, in_port, src_dpid, src_port)
            return

    if in_port is None:
        in_port = ofc.OFPP.CONTROLLER

    # 2. Identify inter-switch ports
    inter_switch_ports = topology.get_inter_switch_ports(formatted_dpid)

    # 3. MAC Learning - only from host-facing ports
    src_mac = ethernet_frame[6:12]
    dst_mac = ethernet_frame[0:6]

    if in_port not in inter_switch_ports:
        mac_to_port[formatted_dpid][src_mac] = in_port

    # 4. Check if broadcast/multicast
    is_broadcast = (dst_mac[0] & 0x01) == 1  # multicast/broadcast bit

    # 5. Find destination
    dst_dpid, dst_port = topology.get_switch_for_mac(dst_mac, mac_to_port)

    # 5a. Broadcast/multicast or unknown unicast -> controlled flood
    if dst_dpid is None or is_broadcast:
        # Only flood from original source (host-facing port)
        if in_port in inter_switch_ports:
            return  # drop to prevent storm

        # Flood on THIS switch (host-facing ports only, excluding in_port)
        host_ports = topology.get_host_ports(formatted_dpid)
        for hp in host_ports:
            if hp != in_port:
                utils.send_packet_out(
                    connection=connection,
                    packet_in_body=packet_in_body,
                    in_port=in_port,
                    out_port=hp,
                    ethernet_frame=ethernet_frame,
                    xid=xid,
                )

        # Forward to ALL other switches and flood on their host-facing ports
        for other_dpid, other_conn in list(switches.items()):
            if other_dpid == formatted_dpid:
                continue

            # Find path from this switch to the other switch
            path = topology.find_path(formatted_dpid, other_dpid)
            if not path:
                continue

            # Send packet out the first hop toward that switch
            # The other switch will receive it as a PACKET_IN and we need
            # to handle it there too. Instead, send PACKET_OUT directly
            # to the remote switch on its host-facing ports.
            remote_host_ports = topology.get_host_ports(other_dpid)
            for hp in remote_host_ports:
                utils.send_raw_packet_out(
                    connection=other_conn,
                    ethernet_frame=ethernet_frame,
                    out_port=hp,
                    xid=xid,
                )
        return

    # 5b. Known unicast on same switch
    if dst_dpid == formatted_dpid:
        utils.install_mac_flow(connection, dst_mac, dst_port, xid)
        utils.send_packet_out(
            connection=connection,
            packet_in_body=packet_in_body,
            in_port=in_port,
            out_port=dst_port,
            ethernet_frame=ethernet_frame,
            xid=xid,
        )
        return

    # 5c. Known unicast on different switch - compute path and install flows
    path = topology.find_path(formatted_dpid, dst_dpid)

    if not path:
        return  # no path, drop

    # Install flows on every intermediate switch
    for hop_dpid, hop_out_port in path:
        hop_connection = switches.get(hop_dpid)
        if hop_connection:
            utils.install_mac_flow(hop_connection, dst_mac, hop_out_port, xid)

    # Install flow on final switch
    dst_connection = switches.get(dst_dpid)
    if dst_connection:
        utils.install_mac_flow(dst_connection, dst_mac, dst_port, xid)

    # Forward this packet out the first hop
    first_out_port = path[0][1]
    utils.send_packet_out(
        connection=connection,
        packet_in_body=packet_in_body,
        in_port=in_port,
        out_port=first_out_port,
        ethernet_frame=ethernet_frame,
        xid=xid,
    )
