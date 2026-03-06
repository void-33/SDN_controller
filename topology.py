import threading
from collections import deque


# Global topology state
# port_map   : dpid -> set of port numbers known on that switch
# links      : (src_dpid, src_port) -> (dst_dpid, dst_port)
# _lock      : protects both dicts for thread-safe access (switches run on separate threads)

port_map = {}   # str dpid -> set(int port_no)
links    = {}   # (str dpid, int port) -> (str dpid, int port)
_lock    = threading.Lock()


# ------------------------------------------------------------------ #
# Port Map                                                             #
# ------------------------------------------------------------------ #

def register_ports(dpid: str, port_nos: list):
    """
    Store the list of port numbers for a switch.
    Called after MULTIPART_REPLY (PORT_DESC) is received.
    """
    with _lock:
        port_map[dpid] = set(port_nos)


def get_ports(dpid: str) -> set:
    """Return the set of known port numbers for a switch."""
    with _lock:
        return set(port_map.get(dpid, set()))


# ------------------------------------------------------------------ #
# Link Map                                                             #
# ------------------------------------------------------------------ #

def add_link(src_dpid: str, src_port: int, dst_dpid: str, dst_port: int):
    """
    Record a directed link:  (src_dpid, src_port) -> (dst_dpid, dst_port)
    LLDP gives us directed links. Both directions will be added separately
    when the neighbour switch sends its own LLDP back.
    """
    with _lock:
        links[(src_dpid, src_port)] = (dst_dpid, dst_port)


def get_neighbours(dpid: str) -> list:
    """
    Return a list of (src_port, dst_dpid, dst_port) tuples
    for every link originating from the given switch.
    """
    with _lock:
        result = []
        for (src_dpid, src_port), (dst_dpid, dst_port) in links.items():
            if src_dpid == dpid:
                result.append((src_port, dst_dpid, dst_port))
        return result


def get_all_links() -> list:
    """Return all known links as a list of (src_dpid, src_port, dst_dpid, dst_port)."""
    with _lock:
        return [
            (src_dpid, src_port, dst_dpid, dst_port)
            for (src_dpid, src_port), (dst_dpid, dst_port) in links.items()
        ]


def print_topology():
    """Pretty-print the current known topology."""
    all_links = get_all_links()
    if not all_links:
        print("[Topology] No links discovered yet.")
        return
    print("[Topology] Discovered Links:")
    for src_dpid, src_port, dst_dpid, dst_port in sorted(all_links):
        print(f"  {src_dpid}:{src_port}  -->  {dst_dpid}:{dst_port}")
    print('Total Links:',len(all_links))


def deregister_switch(dpid: str):
    """
    Remove all topology state for a switch that has disconnected.
    Called from handlers.py when the switch's TCP connection is closed.
    """
    with _lock:
        port_map.pop(dpid, None)
        # Remove directed links that originated from this switch
        stale = [k for k in links if k[0] == dpid]
        for k in stale:
            del links[k]


# ------------------------------------------------------------------ #
# Path Finding                                                         #
# ------------------------------------------------------------------ #

def find_path(src_dpid: str, dst_dpid: str) -> list:
    """
    BFS shortest path between two switches.
    Returns a list of (dpid, out_port) tuples for each hop.

    Example for path S1 -> S2 -> S3:
        [
            ('S1', out_port),   # send out this port on S1 to reach S2
            ('S2', out_port),   # send out this port on S2 to reach S3
        ]
    The final switch (dst_dpid) is NOT included - the caller
    already knows the exact host port from mac_to_port.
    """
    if src_dpid == dst_dpid:
        return []

    # Take a snapshot of links under lock, then BFS without holding lock
    with _lock:
        links_snapshot = dict(links)

    queue   = deque()
    visited = set()
    queue.append((src_dpid, []))
    visited.add(src_dpid)

    while queue:
        current_dpid, path = queue.popleft()

        for (s_dpid, s_port), (d_dpid, d_port) in links_snapshot.items():
            if s_dpid != current_dpid:
                continue
            if d_dpid in visited:
                continue

            new_path = path + [(current_dpid, s_port)]

            if d_dpid == dst_dpid:
                return new_path

            visited.add(d_dpid)
            queue.append((d_dpid, new_path))

    print(f"[BFS] No path found!")
    return []   # no path found


def get_switch_for_mac(mac: bytes, mac_to_port: dict) -> tuple:
    """
    Search all switches for a learned MAC address.
    Returns (dpid, port) or (None, None).
    """
    for dpid, table in mac_to_port.items():
        if mac in table:
            return dpid, table[mac]
    return None, None


def get_inter_switch_ports(dpid: str) -> set:
    """Return the set of ports on dpid that connect to other switches."""
    with _lock:
        return {sp for (sd, sp) in links if sd == dpid}


def get_host_ports(dpid: str) -> set:
    """Return ports on dpid that are NOT inter-switch (i.e. host-facing)."""
    with _lock:
        all_ports = set(port_map.get(dpid, set()))
        inter = {sp for (sd, sp) in links if sd == dpid}
        return all_ports - inter
