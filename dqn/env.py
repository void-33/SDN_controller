import random
import re
import time
from typing import Iterable, Optional

import numpy as np
import requests


STATE_LINKS = 36
METRICS_PER_LINK = 3
STATE_DIM = STATE_LINKS * METRICS_PER_LINK
ACTION_DIM = 5
DEFAULT_BANDWIDTH_BPS = 1_000_000_000.0

SOURCE_HOST = "h1x1"
DEST_HOST = "h3x3"
SOURCE_MAC = "00:00:00:00:01:01"
DEST_MAC = "00:00:00:00:03:03"
SOURCE_DPID = "00:00:00:00:00:00:01:01"
DEST_DPID = "00:00:00:00:00:00:03:03"

ALL_HOSTS = [f"h{row}x{col}" for row in range(1, 4) for col in range(1, 4)]
TRAINING_ENDPOINTS = {SOURCE_HOST, DEST_HOST}
CONGESTION_HOSTS = [host for host in ALL_HOSTS if host not in TRAINING_ENDPOINTS]


class Torus3x3TopoFactory:
    """Creates a Mininet Topo lazily so importing this module does not require Mininet."""

    @staticmethod
    def create():
        from mininet.topo import Topo

        class Torus3x3Topo(Topo):
            def build(self):
                switches = {}
                for row in range(1, 4):
                    for col in range(1, 4):
                        switch_name = f"s{row}x{col}"
                        host_name = f"h{row}x{col}"
                        dpid = f"000000000000{row:02x}{col:02x}"
                        mac = f"00:00:00:00:{row:02x}:{col:02x}"
                        switch = self.addSwitch(switch_name, dpid=dpid)
                        host = self.addHost(host_name, mac=mac)
                        self.addLink(host, switch)
                        switches[(row, col)] = switch

                for row in range(1, 4):
                    for col in range(1, 4):
                        right = (row, (col % 3) + 1)
                        down = ((row % 3) + 1, col)
                        self.addLink(switches[(row, col)], switches[right])
                        self.addLink(switches[(row, col)], switches[down])

        return Torus3x3Topo()


class SDNEnvironment:
    def __init__(
        self,
        api_base: str = "http://127.0.0.1:8000/api",
        controller_ip: str = "127.0.0.1",
        controller_port: int = 6653,
        alpha: float = 1.0,
        beta: float = 1.0,
        request_timeout: float = 5.0,
        settle_seconds: float = 8.0,
    ):
        self.api_base = api_base.rstrip("/")
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.alpha = alpha
        self.beta = beta
        self.request_timeout = request_timeout
        self.settle_seconds = settle_seconds
        self.net = None
        self.paths = []

    def start(self):
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSKernelSwitch, RemoteController

        setLogLevel("info")
        topo = Torus3x3TopoFactory.create()
        self.net = Mininet(
            topo=topo,
            controller=lambda name: RemoteController(
                name,
                ip=self.controller_ip,
                port=self.controller_port,
            ),
            switch=OVSKernelSwitch,
            autoSetMacs=False,
            autoStaticArp=True,
        )
        self.net.start()
        time.sleep(self.settle_seconds)
        self.prime_host_learning()

    def stop(self):
        if self.net is not None:
            self.net.stop()
            self.net = None

    def reset(self):
        if self.net is None:
            self.start()
        self.prime_host_learning()
        self.fetch_paths()
        return self.get_state()

    def prime_host_learning(self):
        if self.net is None:
            return
        self.net.get(SOURCE_HOST).cmd(f"ping -c 1 -W 1 {self.net.get(DEST_HOST).IP()} >/dev/null 2>&1")
        self.net.get(DEST_HOST).cmd(f"ping -c 1 -W 1 {self.net.get(SOURCE_HOST).IP()} >/dev/null 2>&1")

    def get_state(self):
        response = requests.get(f"{self.api_base}/metrics", timeout=self.request_timeout)
        response.raise_for_status()
        metrics = response.json().get("metrics", [])
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

    def fetch_paths(self, src_dpid: str = SOURCE_DPID, dst_dpid: str = DEST_DPID, k: int = ACTION_DIM):
        response = requests.get(
            f"{self.api_base}/k-shortest-paths",
            params={"src": src_dpid, "dst": dst_dpid, "k": k},
            timeout=self.request_timeout,
        )
        response.raise_for_status()
        self.paths = response.json().get("paths", [])
        return self.paths

    def make_congestion(
        self,
        duration_seconds: int = 12,
        bandwidth: str = "10M",
        flow_count: int = 1,
        randomize: bool = True,
        bandwidth_choices: Optional[Iterable[str]] = None,
        cleanup_existing: bool = True,
    ):
        if self.net is None:
            return []

        if cleanup_existing:
            self.close_congestion(hosts=CONGESTION_HOSTS)

        flows = []
        candidates = list(CONGESTION_HOSTS)
        max_flows = min(flow_count, len(candidates) // 2)

        for idx in range(max_flows):
            if randomize:
                src_name, dst_name = random.sample(candidates, 2)
                candidates.remove(src_name)
                candidates.remove(dst_name)
                selected_bandwidth = random.choice(list(bandwidth_choices or [bandwidth]))
                selected_duration = random.randint(
                    max(1, int(duration_seconds * 0.75)),
                    max(1, int(duration_seconds * 1.5)),
                )
            else:
                src_name = candidates[(idx * 2) % len(candidates)]
                dst_name = candidates[(idx * 2 + 1) % len(candidates)]
                selected_bandwidth = bandwidth
                selected_duration = duration_seconds

            src = self.net.get(src_name)
            dst = self.net.get(dst_name)
            server_log = f"/tmp/dqn-iperf-server-{dst_name}.log"
            client_log = f"/tmp/dqn-iperf-client-{src_name}-{dst_name}.log"
            dst.cmd(f"iperf -s -u >{server_log} 2>&1 &")
            src.cmd(
                f"iperf -c {dst.IP()} -u -b {selected_bandwidth} -t {selected_duration} "
                f">{client_log} 2>&1 &"
            )
            flows.append({
                "src": src_name,
                "dst": dst_name,
                "bandwidth": selected_bandwidth,
                "duration_seconds": selected_duration,
            })

        return flows

    def step(self, action_idx: int):
        if not self.paths:
            self.fetch_paths()
        if action_idx < 0 or action_idx >= len(self.paths):
            return self.get_state(), -1_000.0, True, {"reason": "invalid_action"}

        payload = {
            "src_mac": SOURCE_MAC,
            "dst_mac": DEST_MAC,
            "path": self.paths[action_idx],
        }
        response = requests.post(f"{self.api_base}/install-path", json=payload, timeout=self.request_timeout)
        response.raise_for_status()
        install_result = response.json()
        if install_result.get("status") != "success":
            return self.get_state(), -1_000.0, True, install_result

        time.sleep(1.0)
        ping_output = self._probe()
        avg_rtt, packet_loss = self._parse_ping(ping_output)
        reward = -(self.alpha * avg_rtt + self.beta * packet_loss)
        return self.get_state(), reward, False, {
            "avg_rtt_ms": avg_rtt,
            "packet_loss_pct": packet_loss,
            "path": self.paths[action_idx],
        }

    def _probe(self):
        if self.net is None:
            raise RuntimeError("Mininet is not running. Call start() or reset() first.")
        src = self.net.get(SOURCE_HOST)
        dst = self.net.get(DEST_HOST)
        return src.cmd(f"ping -c 5 -i 0.2 -q {dst.IP()}")

    @staticmethod
    def _parse_ping(output: str):
        loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
        packet_loss = float(loss_match.group(1)) if loss_match else 100.0

        rtt_match = re.search(r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)/", output)
        avg_rtt = float(rtt_match.group(1)) if rtt_match else 1_000.0
        return avg_rtt, packet_loss

    def close_congestion(self, hosts: Optional[Iterable[str]] = None):
        if self.net is None:
            return
        host_names = hosts or ALL_HOSTS
        for host_name in host_names:
            self.net.get(host_name).cmd("pkill -f iperf >/dev/null 2>&1")
