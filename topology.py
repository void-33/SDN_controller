import threading


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
