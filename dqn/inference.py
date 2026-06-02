import numpy as np
import torch

from dqn.agent import DQN
from dqn.env import ACTION_DIM, DEFAULT_BANDWIDTH_BPS, STATE_DIM, STATE_LINKS
import routing
import topology


class DQNPathPolicy:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = DQN(STATE_DIM, ACTION_DIM).to(self.device)

        checkpoint = torch.load(model_path, map_location=self.device)
        state_dict = checkpoint.get("policy_state_dict", checkpoint)
        self.model.load_state_dict(state_dict)
        self.model.eval()

    def select_action_path(self, src_dpid: str, dst_dpid: str):
        paths = routing.k_shortest_hop_paths(src_dpid, dst_dpid, ACTION_DIM)
        if not paths:
            raise RuntimeError("no candidate paths available")

        state = build_state_from_topology()
        state_tensor = torch.as_tensor(state, dtype=torch.float32, device=self.device).unsqueeze(0)
        with torch.no_grad():
            q_values = self.model(state_tensor).squeeze(0)

        ranked_actions = torch.argsort(q_values, descending=True).tolist()
        for action in ranked_actions:
            if action < len(paths):
                return int(action), paths[action]

        raise RuntimeError("DQN selected no valid action for available candidate paths")


def build_state_from_topology():
    metrics = []
    for src_dpid, src_port, dst_dpid, dst_port, _last_seen, cost in topology.get_all_links():
        info = topology.get_link_info(src_dpid, src_port) or {}
        metrics.append({
            "src_dpid": src_dpid,
            "src_port": src_port,
            "dst_dpid": dst_dpid,
            "dst_port": dst_port,
            "cost": cost,
            "latency_ms": info.get("latency_ms", 1.0),
            "bandwidth_bps": info.get("bandwidth_bps", DEFAULT_BANDWIDTH_BPS),
            "loss": info.get("loss", 0.0),
        })

    sorted_links = sorted(
        metrics,
        key=lambda item: (
            item.get("src_dpid", ""),
            int(item.get("src_port", 0)),
            item.get("dst_dpid", ""),
            int(item.get("dst_port", 0)),
        ),
    )

    state = []
    for link in sorted_links[:STATE_LINKS]:
        latency = float(link.get("latency_ms") or 1.0)
        bandwidth = float(link.get("bandwidth_bps") or DEFAULT_BANDWIDTH_BPS)
        loss = float(link.get("loss") or 0.0)
        state.extend([latency, bandwidth / DEFAULT_BANDWIDTH_BPS, loss])

    while len(state) < STATE_DIM:
        state.extend([1.0, 1.0, 0.0])

    return np.array(state[:STATE_DIM], dtype=np.float32)

