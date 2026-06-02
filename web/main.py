from fastapi import FastAPI, WebSocket, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import threading
import sys
import os
from typing import List, Tuple
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import topology
import handlers
import controller
import utils
import routing

app = FastAPI()

@app.on_event("startup")
def startup_event():
    if os.environ.get("SDN_SKIP_CONTROLLER_STARTUP") == "1":
        return

    # Start the SDN controller in a background thread
    controller_thread = threading.Thread(target=controller.start_controller, daemon=True)
    controller_thread.start()
    print("Started controller thread")

# Serve static files (frontend)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

@app.get("/")
def get_index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


def _endpoint_token(dpid: str, port: int) -> str:
    return f"{dpid}:{port}"


def _switch_link_edge_id(src_dpid: str, src_port: int, dst_dpid: str, dst_port: int) -> str:
    a = _endpoint_token(src_dpid, src_port)
    b = _endpoint_token(dst_dpid, dst_port)
    pair_key = "||".join(sorted([a, b]))
    return f"link:{pair_key}"


def _host_link_edge_id(host_id: str, switch_dpid: str, switch_port: int) -> str:
    return f"hostlink:{host_id}||{switch_dpid}:{switch_port}"


def _parse_host_mac(host_id: str):
    if not host_id.startswith("host:"):
        return None
    mac_str = host_id[len("host:"):]
    try:
        return bytes.fromhex(mac_str.replace(":", ""))
    except Exception:
        return None


def _resolve_node_endpoint(node_id: str, switches: set):
    if node_id.startswith("host:"):
        mac_bytes = _parse_host_mac(node_id)
        if not mac_bytes:
            return None
        dpid, port = topology.get_switch_for_mac(mac_bytes, handlers.mac_to_port)
        if not dpid:
            return None
        return {
            "type": "host",
            "node_id": node_id,
            "mac": mac_bytes,
            "switch_dpid": dpid,
            "switch_port": port,
        }

    # switch
    if node_id not in switches:
        return None
    return {
        "type": "switch",
        "node_id": node_id,
        "mac": None,
        "switch_dpid": node_id,
        "switch_port": None,
    }

@app.get("/api/topology")
def get_topology():
    switches = list(topology.port_map.keys())
    links = []
    hosts = []
    host_links = []
    if hasattr(topology, 'get_all_links'):
        for l in topology.get_all_links():
            # l format: (src_dpid, src_port, dst_dpid, dst_port, last_seen, cost)
            cost = l[5] if len(l) > 5 else 1
            links.append({
                "src_dpid": l[0],
                "src_port": l[1],
                "dst_dpid": l[2],
                "dst_port": l[3],
                "cost": cost
            })

    active_switches = set(switches)
    if hasattr(handlers, 'mac_to_port'):
        seen_hosts = set()
        for dpid, table in handlers.mac_to_port.items():
            if dpid not in active_switches:
                continue
            inter_switch_ports = topology.get_inter_switch_ports(dpid)
            for mac, port in table.items():
                if port in inter_switch_ports:
                    continue
                mac_str = mac.hex(':') if isinstance(mac, (bytes, bytearray)) else str(mac)
                host_id = f"host:{mac_str}"
                if host_id not in seen_hosts:
                    hosts.append({"id": host_id, "mac": mac_str})
                    seen_hosts.add(host_id)
                host_links.append({
                    "host_id": host_id,
                    "switch_dpid": dpid,
                    "switch_port": port
                })

    return {"switches": switches, "links": links, "hosts": hosts, "host_links": host_links}


@app.get("/api/path")
def get_path(src: str = Query(...), dst: str = Query(...)):
    switches = set(topology.port_map.keys())

    src_ep = _resolve_node_endpoint(src, switches)
    dst_ep = _resolve_node_endpoint(dst, switches)
    if not src_ep or not dst_ep:
        return {"found": False, "edge_ids": [], "huh": False}

    src_sw = src_ep["switch_dpid"]
    dst_sw = dst_ep["switch_dpid"]

    # Prefer existing active flow state for host->host so UI path matches actual forwarding.
    flow_path = None
    if src_ep["type"] == "host" and dst_ep["type"] == "host":
        flow_key = (src_ep["mac"], dst_ep["mac"])
        flow_info = handlers.active_flows.get(flow_key)
        if flow_info:
            flow_path = list(flow_info.get("path", []))

    if flow_path is None:
        if src_sw == dst_sw:
            flow_path = []
        else:
            decision = routing.select_path(src_sw, dst_sw, src_ep["mac"], dst_ep["mac"])
            flow_path = decision.path
            if not flow_path:
                return {"found": False, "edge_ids": [], "ohno": decision}

    edge_ids = []
    seen = set()

    # Host attachment at source
    if src_ep["type"] == "host":
        eid = _host_link_edge_id(src_ep["node_id"], src_ep["switch_dpid"], src_ep["switch_port"])
        if eid not in seen:
            edge_ids.append(eid)
            seen.add(eid)

    # Inter-switch hops
    for hop_dpid, hop_out_port in flow_path:
        dst_link = topology.get_link_destination(hop_dpid, hop_out_port)
        if not dst_link:
            continue
        dst_dpid, dst_port = dst_link
        eid = _switch_link_edge_id(hop_dpid, hop_out_port, dst_dpid, dst_port)
        if eid not in seen:
            edge_ids.append(eid)
            seen.add(eid)

    # Host attachment at destination
    if dst_ep["type"] == "host":
        eid = _host_link_edge_id(dst_ep["node_id"], dst_ep["switch_dpid"], dst_ep["switch_port"])
        if eid not in seen:
            edge_ids.append(eid)
            seen.add(eid)

    return {"found": True, "edge_ids": edge_ids}

@app.get("/api/flows")
def get_flows():
    flows = []
    if hasattr(handlers, 'active_flows'):
        for k, v in handlers.active_flows.items():
            flows.append({
                "src_mac": k[0].hex(':') if isinstance(k[0], (bytes, bytearray)) else str(k[0]),
                "dst_mac": k[1].hex(':') if isinstance(k[1], (bytes, bytearray)) else str(k[1]),
                "path": v.get('path'),
                "dst_dpid": v.get('dst_dpid'),
                "dst_port": v.get('dst_port'),
                "routing_mode": v.get('routing_mode'),
                "dqn_action": v.get('dqn_action'),
            })
    return {"flows": flows}

class LinkCostUpdate(BaseModel):
    src_dpid: str
    dst_dpid: str
    cost: int


class RoutingModeUpdate(BaseModel):
    mode: str


class ClearFlowRequest(BaseModel):
    src_mac: str = "00:00:00:00:01:01"
    dst_mac: str = "00:00:00:00:03:03"

@app.post("/api/link_cost")
def update_link_cost(data: LinkCostUpdate):
    topology.set_hardcoded_cost(data.src_dpid, data.dst_dpid, data.cost)
    return {"status": "ok"}


@app.get("/api/routing-mode")
def get_routing_mode():
    return {
        "mode": routing.get_mode(),
        "valid_modes": sorted(routing.VALID_ROUTING_MODES),
        "dqn_model_path": routing.DQN_MODEL_PATH,
        "dqn_available": routing.get_dqn_availability_error() is None,
    }


@app.post("/api/routing-mode")
def update_routing_mode(req: RoutingModeUpdate):
    decision = routing.set_mode(req.mode)
    if decision.error:
        return {"status": "error", "mode": routing.get_mode(), "message": decision.error}
    return {"status": "success", "mode": routing.get_mode()}


@app.post("/api/clear-flow")
def clear_flow(req: ClearFlowRequest):
    src_mac = bytes.fromhex(req.src_mac.replace(":", ""))
    dst_mac = bytes.fromhex(req.dst_mac.replace(":", ""))
    old_flow = handlers.clear_flow(src_mac, dst_mac)
    old_flow_rev = handlers.clear_flow(dst_mac, src_mac)
    return {
        "status": "success",
        "cleared": old_flow is not None,
        "cleared_rev": old_flow_rev is not None,
        "src_mac": req.src_mac,
        "dst_mac": req.dst_mac,
    }


@app.get("/api/metrics")
def get_metrics():
    metrics = []
    for link in topology.get_all_links():
        src_dpid, src_port, dst_dpid, dst_port, _last_seen, cost = link
        info = topology.get_link_info(src_dpid, src_port) or {}
        metrics.append({
            "src_dpid": src_dpid,
            "src_port": src_port,
            "dst_dpid": dst_dpid,
            "dst_port": dst_port,
            "cost": cost,
            "latency_ms": info.get("latency_ms", 1.0),
            "bandwidth_bps": info.get("bandwidth_bps", 1_000_000_000.0),
            "loss": info.get("loss", 0.0),
        })
    return {"metrics": metrics}


def _k_shortest_simple_paths(src: str, dst: str, k: int) -> list:
    """Return up to k simple switch paths ordered by hop count."""
    return routing.k_shortest_hop_paths(src, dst, k)


@app.get("/api/k-shortest-paths")
def get_k_shortest_paths(src: str = Query(...), dst: str = Query(...), k: int = Query(5, ge=1, le=20)):
    return {"paths": _k_shortest_simple_paths(src, dst, k)}


class InstallPathRequest(BaseModel):
    src_mac: str
    dst_mac: str
    path: List[Tuple[str, int]]
    routing_mode: str = "api"


@app.post("/api/install-path")
def install_selected_path(req: InstallPathRequest):
    src_mac = bytes.fromhex(req.src_mac.replace(":", ""))
    dst_mac = bytes.fromhex(req.dst_mac.replace(":", ""))
    path = [(dpid, int(out_port)) for dpid, out_port in req.path]

    dst_dpid, dst_port = topology.get_switch_for_mac(dst_mac, handlers.mac_to_port)
    if not dst_dpid:
        return {"status": "error", "message": "Destination host unknown"}

    flow_key = (src_mac, dst_mac)
    old_flow = handlers.active_flows.get(flow_key)
    if old_flow:
        for hop_dpid, _hop_out_port in old_flow.get("path", []):
            hop_connection = handlers.switches.get(hop_dpid)
            if hop_connection:
                utils.remove_mac_flow(hop_connection, dst_mac)
        old_dst_connection = handlers.switches.get(old_flow.get("dst_dpid"))
        if old_dst_connection:
            utils.remove_mac_flow(old_dst_connection, dst_mac)

    for hop_dpid, hop_out_port in path:
        hop_connection = handlers.switches.get(hop_dpid)
        if hop_connection:
            utils.install_mac_flow(hop_connection, dst_mac, hop_out_port, xid=0)

    dst_connection = handlers.switches.get(dst_dpid)
    if dst_connection:
        utils.install_mac_flow(dst_connection, dst_mac, dst_port, xid=0)

    handlers.active_flows[flow_key] = {
        "path": path,
        "dst_dpid": dst_dpid,
        "dst_port": dst_port,
        "rl_managed": True,
        "routing_mode": req.routing_mode,
        "dqn_action": None,
    }

    return {"status": "success", "message": "Path installed successfully"}

@app.websocket("/ws/topology")
async def websocket_topology(websocket: WebSocket):
    await websocket.accept()
    # Example: send topology every 2 seconds
    import asyncio
    while True:
        switches = list(topology.port_map.keys())
        links = []
        hosts = []
        host_links = []
        if hasattr(topology, 'get_all_links'):
            for l in topology.get_all_links():
                cost = l[5] if len(l) > 5 else 1
                links.append({
                    "src_dpid": l[0],
                    "src_port": l[1],
                    "dst_dpid": l[2],
                    "dst_port": l[3],
                    "cost": cost
                })

        active_switches = set(switches)
        if hasattr(handlers, 'mac_to_port'):
            seen_hosts = set()
            for dpid, table in handlers.mac_to_port.items():
                if dpid not in active_switches:
                    continue
                inter_switch_ports = topology.get_inter_switch_ports(dpid)
                for mac, port in table.items():
                    if port in inter_switch_ports:
                        continue
                    mac_str = mac.hex(':') if isinstance(mac, (bytes, bytearray)) else str(mac)
                    host_id = f"host:{mac_str}"
                    if host_id not in seen_hosts:
                        hosts.append({"id": host_id, "mac": mac_str})
                        seen_hosts.add(host_id)
                    host_links.append({
                        "host_id": host_id,
                        "switch_dpid": dpid,
                        "switch_port": port
                    })

        await websocket.send_json({"switches": switches, "links": links, "hosts": hosts, "host_links": host_links})
        # Sync the UI socket refresh closely to the LLDP interval so the UI 
        # isn't over or under spinning when the backend acquires new state
        await asyncio.sleep(5)
