import utils
import ofproto.constants as ofc
from ofproto.packet_in import OFPPacketIn
from ofproto.multipart import OFPMultipartReply
from ofproto.lldp import LLDPPacket, ETHERTYPE_LLDP
import topology
import routing
import struct
import threading

import time

# Based on standard SDN practices and OpenFlow guidelines, 
# LLDP intervals are usually 3 to 10 seconds. 5 seconds is a good default 
# that prevents controller flooding while keeping pathfinding responsive.
LLDP_INTERVAL = 5
STATS_INTERVAL = 5

# Composite cost weights (tunable).
ALPHA = 1.0   # latency weight
BETA = 1.0    # bandwidth weight
GAMMA = 1.0   # loss weight

# Default link capacity in bps (used when port speed is unknown).
DEFAULT_LINK_CAPACITY_BPS = 1_000_000_000

# Reroute only if the new path improves cost by at least this ratio.
COST_IMPROVEMENT_THRESHOLD = 0.20


switches    = {}
mac_to_port = {}
_pending_ports = {}
_pending_port_speeds = {}
_port_stats_state = {}

# Track active flows: (src_mac, dst_mac) -> {'path': [(dpid, out_port), ...], 'dst_dpid': str, 'dst_port': int}
active_flows = {}


def clear_flow(src_mac: bytes, dst_mac: bytes):
    """Remove controller-tracked and switch-installed rules for a host flow."""
    flow_key = (bytes(src_mac), bytes(dst_mac))
    old_flow = active_flows.pop(flow_key, None)

    # Remove from all connected switches for fair benchmark mode switching.
    for connection in list(switches.values()):
        try:
            utils.remove_mac_flow(connection, dst_mac)
        except Exception:
            pass

    return old_flow


def start_lldp_sender():
    t = threading.Thread(target=_lldp_sender_loop, daemon=True, name="lldp-sender")
    t.start()
    print(f"[LLDP] Periodic sender started (interval={LLDP_INTERVAL}s)")


def start_stats_sender():
    t = threading.Thread(target=_stats_sender_loop, daemon=True, name="stats-sender")
    t.start()
    print(f"[STATS] Periodic sender started (interval={STATS_INTERVAL}s)")


def _get_port_metrics(dpid: str, port_no: int) -> tuple:
    port_stats = _port_stats_state.get(dpid, {}).get(port_no)
    if not port_stats:
        return None, None
    return port_stats.get('available_bps'), port_stats.get('loss')


def _compute_link_cost(latency_ms: float, capacity_bps: float, available_bps: float, loss: float) -> float:
    if latency_ms is None:
        latency_ms = 1.0
    if capacity_bps <= 0:
        capacity_bps = DEFAULT_LINK_CAPACITY_BPS
    if available_bps is None or available_bps <= 0:
        available_bps = max(1.0, capacity_bps)
    if loss is None:
        loss = 0.0
    return (ALPHA * latency_ms) + (BETA * (capacity_bps / available_bps)) + (GAMMA * loss)


def _recompute_link_cost(src_dpid: str, src_port: int, latency_ms: float = None,
                          available_bps: float = None, loss: float = None):
    info = topology.get_link_info(src_dpid, src_port)
    if not info:
        return
    latency_ms = latency_ms if latency_ms is not None else info.get('latency_ms')
    available_bps = available_bps if available_bps is not None else info.get('bandwidth_bps')
    loss = loss if loss is not None else info.get('loss')
    capacity_bps = topology.get_port_speed(src_dpid, src_port) or DEFAULT_LINK_CAPACITY_BPS
    cost = _compute_link_cost(latency_ms, capacity_bps, available_bps, loss)
    topology.update_link_metrics(
        src_dpid=src_dpid,
        src_port=src_port,
        cost=cost,
        latency_ms=latency_ms,
        bandwidth_bps=available_bps,
        loss=loss,
    )


def _reroute_affected_flows(removed_links: list, reason: str):
    """Reroute flows that traverse any removed directed link."""
    for src_dpid, src_port, dst_dpid, dst_port in removed_links:
        print(f"[TOPOLOGY] Link removed ({reason}): {src_dpid}:{src_port} -> {dst_dpid}:{dst_port}")

        affected_flows = []
        for flow_key, flow_info in list(active_flows.items()):
            path = flow_info['path']
            for hop_dpid, hop_out_port in path:
                if hop_dpid == src_dpid and hop_out_port == src_port:
                    affected_flows.append(flow_key)
                    break

        for flow_key in affected_flows:
            src_mac, dst_mac = flow_key
            flow_info = active_flows[flow_key]
            dst_dpid = flow_info['dst_dpid']
            dst_port = flow_info['dst_port']

            if not flow_info['path']:
                continue

            src_dpid_for_flow = flow_info['path'][0][0]
            decision = routing.select_path(src_dpid_for_flow, dst_dpid, src_mac, dst_mac)
            new_path = decision.path

            # Always remove old rules first (best effort)
            for hop_dpid, _ in flow_info['path']:
                hop_conn = switches.get(hop_dpid)
                if hop_conn:
                    utils.remove_mac_flow(hop_conn, dst_mac)
            dst_conn = switches.get(dst_dpid)
            if dst_conn:
                utils.remove_mac_flow(dst_conn, dst_mac)

            if not new_path:
                print(f"[REROUTE] No alternate path for flow {src_mac.hex(':')}->{dst_mac.hex(':')}, dropped old rules.")
                del active_flows[flow_key]
                continue

            for hop_dpid, hop_out_port in new_path:
                hop_conn = switches.get(hop_dpid)
                if hop_conn:
                    utils.install_mac_flow(hop_conn, dst_mac, hop_out_port, xid=0)

            dst_conn = switches.get(dst_dpid)
            if dst_conn:
                utils.install_mac_flow(dst_conn, dst_mac, dst_port, xid=0)

            active_flows[flow_key]['path'] = list(new_path)
            active_flows[flow_key]['routing_mode'] = decision.routing_mode
            active_flows[flow_key]['dqn_action'] = decision.action
            print(f"[REROUTE] Flow {src_mac.hex(':')}->{dst_mac.hex(':')} rerouted.")

def _check_for_better_paths():
    """Periodically checks if a cheaper path is available for active flows."""
    if routing.get_mode() != "cost":
        return

    for flow_key, flow_info in list(active_flows.items()):
        if flow_info.get('rl_managed'):
            continue

        src_mac, dst_mac = flow_key
        dst_dpid = flow_info['dst_dpid']
        dst_port = flow_info['dst_port']
        current_path = flow_info['path']
        
        if not current_path: continue
        
        src_dpid = current_path[0][0]
        decision = routing.select_path(src_dpid, dst_dpid, src_mac, dst_mac)
        new_path = decision.path
        
        # If a path exists and it's structurally different from the current path
        if new_path and new_path != current_path:
            current_cost = _path_cost(current_path)
            new_cost = _path_cost(new_path)
            if new_cost >= current_cost * (1.0 - COST_IMPROVEMENT_THRESHOLD):
                continue
            print(f"[OPTIMIZATION] Better path found for {src_mac.hex(':')}->{dst_mac.hex(':')}, rerouting...")
            
            # Remove old flow rules
            for hop_dpid, _ in current_path:
                hop_conn = switches.get(hop_dpid)
                if hop_conn:
                    utils.remove_mac_flow(hop_conn, dst_mac)
            dst_conn = switches.get(dst_dpid)
            if dst_conn:
                utils.remove_mac_flow(dst_conn, dst_mac)
                
            # Install new flow rules
            for hop_dpid, hop_out_port in new_path:
                hop_conn = switches.get(hop_dpid)
                if hop_conn:
                    utils.install_mac_flow(hop_conn, dst_mac, hop_out_port, xid=0)
            dst_conn = switches.get(dst_dpid)
            if dst_conn:
                utils.install_mac_flow(dst_conn, dst_mac, dst_port, xid=0)
                
            active_flows[flow_key]['path'] = list(new_path)
            active_flows[flow_key]['routing_mode'] = decision.routing_mode
            active_flows[flow_key]['dqn_action'] = decision.action


def _path_cost(path: list) -> float:
    total = 0.0
    for hop_dpid, hop_out_port in path:
        info = topology.get_link_info(hop_dpid, hop_out_port)
        if not info:
            total += 1.0
            continue
        total += float(info.get('cost', 1.0))
    return total

def _lldp_sender_loop():
    stop = threading.Event()
    LINK_TIMEOUT = 2 * LLDP_INTERVAL

    while not stop.wait(LLDP_INTERVAL):
        # Send LLDP packets
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


        # Remove stale links and reroute affected flows
        removed_links = topology.remove_stale_links(LINK_TIMEOUT)
        if removed_links:
            _reroute_affected_flows(removed_links, reason="lldp-timeout")
            
        # Check if newer, cheaper paths are available for current flows
        _check_for_better_paths()

        # Topology logging intentionally disabled to keep console output clean.


def _stats_sender_loop():
    stop = threading.Event()
    while not stop.wait(STATS_INTERVAL):
        for dpid, connection in list(switches.items()):
            try:
                utils.send_port_stats_request(connection, xid=0)
            except Exception:
                pass


def handle_switch_connection(connection, address):
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

            elif header.message_type == ofc.OFPT.PORT_STATUS:
                if not formatted_dpid:
                    continue
                handle_port_status(
                    connection=connection,
                    body_data=body_data,
                    formatted_dpid=formatted_dpid,
                )

        except Exception as e:
            print(f"Error with {address}:{e}")
            break

    connection.close()
    utils.release_send_lock(connection)
    if formatted_dpid and switches.get(formatted_dpid) is connection:
        switches.pop(formatted_dpid, None)
        # Cleanup learned state for this switch so stale hosts do not remain
        mac_to_port.pop(formatted_dpid, None)
        _pending_ports.pop(formatted_dpid, None)

        # Remove switch from topology and trigger reroute for all affected flows.
        # This also clears stale rules on surviving switches for paths that
        # previously traversed the disconnected switch.
        removed_links = topology.deregister_switch(formatted_dpid)
        if removed_links:
            _reroute_affected_flows(removed_links, reason="switch-disconnect")
    print(f"Switch {address} disconnected")


def handle_features_reply(connection, body_data, address, switches, mac_to_port, xid):
    dpid = utils.unpack_dpid(body_data)
    dpid_hex = f"{dpid:016x}"
    formatted_dpid = ":".join(dpid_hex[i : i + 2] for i in range(0, 16, 2))

    switches[formatted_dpid] = connection

    # Reset learning table on every (re)connect to avoid stale host entries
    mac_to_port[formatted_dpid] = {}

    utils.send_table_miss_flow(connection)
    utils.send_port_desc_request(connection, xid=2)

    return formatted_dpid


def handle_multipart_reply(body_data, formatted_dpid, connection, xid):
    reply = OFPMultipartReply.parse(body_data)
    if reply.type == ofc.OFPMP.PORT_DESC:
        if formatted_dpid not in _pending_ports:
            _pending_ports[formatted_dpid] = []
            _pending_port_speeds[formatted_dpid] = {}

        for port in reply.ports:
            if port.port_no < 0xFFFFFF00:
                _pending_ports[formatted_dpid].append(port.port_no)
                speed_kbps = port.curr_speed or port.max_speed
                if speed_kbps:
                    _pending_port_speeds[formatted_dpid][port.port_no] = int(speed_kbps) * 1000

        if not reply.has_more:
            port_nos = _pending_ports.pop(formatted_dpid, [])
            port_speeds = _pending_port_speeds.pop(formatted_dpid, {})
            topology.register_ports(formatted_dpid, port_nos)
            topology.register_port_speeds(formatted_dpid, port_speeds)

            dpid_int = int(formatted_dpid.replace(':', ''), 16)
            for port_no in port_nos:
                utils.send_lldp_out(connection, dpid_int, port_no, xid)
    elif reply.type == ofc.OFPMP.PORT_STATS:
        _handle_port_stats_reply(formatted_dpid, reply)


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
                ts       = lldp_pkt.get_timestamp()
                if src_mac and src_port is not None and in_port is not None:
                    src_dpid = '00:00:' + ':'.join(f'{b:02x}' for b in src_mac)
                    
                    # Calculate dynamic cost (latency in ms)
                    latency = None
                    if ts is not None:
                        latency = (time.time() - ts) * 1000  # convert to ms

                    available_bps, loss = _get_port_metrics(formatted_dpid, in_port)
                    capacity_bps = topology.get_port_speed(formatted_dpid, in_port) or DEFAULT_LINK_CAPACITY_BPS
                    composite_cost = _compute_link_cost(latency, capacity_bps, available_bps, loss)

                    # Add only observed direction
                    topology.add_link(
                        src_dpid,
                        src_port,
                        formatted_dpid,
                        in_port,
                        cost=composite_cost,
                        latency_ms=latency,
                        bandwidth_bps=available_bps,
                        loss=loss,
                    )
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
    decision = routing.select_path(formatted_dpid, dst_dpid, bytes(src_mac), bytes(dst_mac))
    path = decision.path

    if not path:
        if decision.error:
            print(f"[ROUTING] {decision.error}")
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

    # Track the flow and its path for rerouting
    flow_key = (bytes(src_mac), bytes(dst_mac))
    active_flows[flow_key] = {
        'path': list(path),
        'dst_dpid': dst_dpid,
        'dst_port': dst_port,
        'routing_mode': decision.routing_mode,
        'dqn_action': decision.action,
    }

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
    return


def _handle_port_stats_reply(formatted_dpid: str, reply: OFPMultipartReply):
    now = time.time()
    dpid_stats = _port_stats_state.setdefault(formatted_dpid, {})

    for stat in reply.port_stats:
        port_no = stat.port_no
        if port_no >= 0xFFFFFF00:
            continue

        prev = dpid_stats.get(port_no)
        dpid_stats[port_no] = {
            'tx_bytes': stat.tx_bytes,
            'tx_packets': stat.tx_packets,
            'tx_errors': stat.tx_errors,
            'ts': now,
        }

        if not prev:
            continue

        delta_t = now - prev.get('ts', now)
        if delta_t <= 0:
            continue

        delta_tx_bytes = max(0, stat.tx_bytes - prev.get('tx_bytes', 0))
        delta_tx_packets = max(0, stat.tx_packets - prev.get('tx_packets', 0))
        delta_tx_errors = max(0, stat.tx_errors - prev.get('tx_errors', 0))

        tx_rate_bps = (delta_tx_bytes * 8) / delta_t
        capacity_bps = topology.get_port_speed(formatted_dpid, port_no) or DEFAULT_LINK_CAPACITY_BPS
        available_bps = max(1.0, capacity_bps - tx_rate_bps)
        loss = (delta_tx_errors / max(delta_tx_packets, 1)) if delta_tx_packets > 0 else 0.0

        dpid_stats[port_no]['available_bps'] = available_bps
        dpid_stats[port_no]['loss'] = loss

        _recompute_link_cost(
            src_dpid=formatted_dpid,
            src_port=port_no,
            available_bps=available_bps,
            loss=loss,
        )


def handle_port_status(connection, body_data, formatted_dpid):
    """
    Handle OFPT_PORT_STATUS for immediate link down/up events.
    body_data layout (OpenFlow 1.3): reason(1), pad(7), ofp_port desc...
    """
    if len(body_data) < 48:
        return

    reason = body_data[0]
    port_no = struct.unpack('!I', body_data[8:12])[0]
    state = struct.unpack('!I', body_data[44:48])[0]

    # Ignore reserved/non-physical ports
    if port_no >= 0xFFFFFF00:
        return

    link_down = (state & int(ofc.OFPPS.LINK_DOWN)) != 0

    if link_down or reason == 1:  # reason==DELETE
        topology.set_port_live(formatted_dpid, port_no, is_live=False)
        removed_links = topology.remove_links_for_port(formatted_dpid, port_no)
        if removed_links:
            _reroute_affected_flows(removed_links, reason="port-status")
    else:
        topology.set_port_live(formatted_dpid, port_no, is_live=True)
        # Probe immediately so the link can be rediscovered without waiting a full cycle
        conn = switches.get(formatted_dpid)
        if conn:
            try:
                dpid_int = int(formatted_dpid.replace(':', ''), 16)
                utils.send_lldp_out(conn, dpid_int, port_no, xid=0)
            except Exception:
                pass
