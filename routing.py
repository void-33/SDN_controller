import os
import threading
from dataclasses import dataclass
from typing import Optional

import topology


VALID_ROUTING_MODES = {"hop", "cost", "dqn"}
DEFAULT_ROUTING_MODE = os.environ.get("SDN_ROUTING_MODE", "cost").lower()
DQN_MODEL_PATH = os.environ.get("SDN_DQN_MODEL", os.path.join("dqn", "dqn_model.pth"))

SOURCE_MAC = bytes.fromhex("000000000101")
DEST_MAC = bytes.fromhex("000000000303")
SOURCE_DPID = "00:00:00:00:00:00:01:01"
DEST_DPID = "00:00:00:00:00:00:03:03"

_mode_lock = threading.Lock()
_routing_mode = DEFAULT_ROUTING_MODE if DEFAULT_ROUTING_MODE in VALID_ROUTING_MODES else "cost"
_dqn_policy = None


@dataclass
class RouteDecision:
    path: list
    routing_mode: str
    action: Optional[int] = None
    error: Optional[str] = None


def get_mode() -> str:
    with _mode_lock:
        return _routing_mode


def set_mode(mode: str) -> RouteDecision:
    global _routing_mode

    normalized = mode.lower()
    if normalized not in VALID_ROUTING_MODES:
        return RouteDecision([], get_mode(), error=f"invalid routing mode: {mode}")

    if normalized == "dqn":
        availability_error = get_dqn_availability_error()
        if availability_error:
            return RouteDecision([], get_mode(), error=availability_error)

    with _mode_lock:
        _routing_mode = normalized

    return RouteDecision([], normalized)


def get_dqn_availability_error() -> Optional[str]:
    if not os.path.exists(DQN_MODEL_PATH):
        return f"DQN model not found at {DQN_MODEL_PATH}"

    try:
        get_dqn_policy()
    except Exception as exc:
        return f"DQN policy unavailable: {exc}"
    return None


def get_dqn_policy():
    global _dqn_policy
    if _dqn_policy is None:
        from dqn.inference import DQNPathPolicy

        _dqn_policy = DQNPathPolicy(DQN_MODEL_PATH)
    return _dqn_policy


def _reverse_hops(path: list) -> list:
    if not path:
        return []

    hop_edges = []
    for hop_dpid, hop_out_port in path:
        dst = topology.get_link_destination(hop_dpid, hop_out_port)
        if not dst:
            raise RuntimeError("missing link destination for hop")
        dst_dpid, _dst_port = dst
        hop_edges.append((hop_dpid, dst_dpid))

    reverse_ports = {}
    for src_dpid, src_port, dst_dpid, _dst_port, _last_seen, _cost in topology.get_all_links():
        reverse_ports[(src_dpid, dst_dpid)] = src_port

    reversed_hops = []
    for from_dpid, to_dpid in reversed(hop_edges):
        out_port = reverse_ports.get((to_dpid, from_dpid))
        if out_port is None:
            raise RuntimeError("missing reverse link port")
        reversed_hops.append((to_dpid, out_port))

    return reversed_hops


def select_path(src_dpid: str, dst_dpid: str, src_mac: bytes = None, dst_mac: bytes = None) -> RouteDecision:
    mode = get_mode()

    if mode == "hop":
        return RouteDecision(topology.find_path_bfs(src_dpid, dst_dpid), "hop")

    if mode == "cost":
        return RouteDecision(topology.find_path_dijkstra(src_dpid, dst_dpid), "cost")

    if not _is_supported_dqn_flow(src_dpid, dst_dpid, src_mac, dst_mac) and not _is_supported_dqn_flow(dst_dpid, src_dpid, dst_mac, src_mac):
        return RouteDecision(
            [],
            "dqn",
            error="DQN routing only supports h1x1 -> h3x3 in the Torus(3,3) demo",
        )


    try:
        revpath = _is_supported_dqn_flow(dst_dpid, src_dpid, dst_mac, src_mac)
        action, path = get_dqn_policy().select_action_path(SOURCE_DPID, DEST_DPID)
        path = _reverse_hops(path) if revpath else path
        return RouteDecision(path, "dqn", action=action)
    except Exception as exc:
        return RouteDecision([], "dqn", error=f"DQN route selection failed: {exc}")


def k_shortest_hop_paths(src: str, dst: str, k: int) -> list:
    """Return deterministic simple paths ordered by hop count, ignoring dynamic link costs."""
    if k <= 0:
        return []

    adjacency = {}
    for src_dpid, src_port, dst_dpid, _dst_port, _last_seen, _cost in topology.get_all_links():
        adjacency.setdefault(src_dpid, []).append((dst_dpid, src_port, 1.0))

    queue = [(0.0, src, [])]
    results = []

    while queue and len(results) < k:
        cost_so_far, current, hops = queue.pop(0)
        if current == dst:
            results.append(hops)
            continue

        visited = {hop_dpid for hop_dpid, _port in hops}
        visited.add(current)

        for next_dpid, out_port, edge_cost in sorted(adjacency.get(current, [])):
            if next_dpid in visited:
                continue
            next_hops = hops + [(current, out_port)]
            queue.append((cost_so_far + edge_cost, next_dpid, next_hops))

        queue.sort(key=lambda item: (item[0], len(item[2]), item[2]))

    return results


def _is_supported_dqn_flow(src_dpid: str, dst_dpid: str, src_mac: bytes = None, dst_mac: bytes = None) -> bool:
    if src_dpid != SOURCE_DPID or dst_dpid != DEST_DPID:
        return False
    return True
