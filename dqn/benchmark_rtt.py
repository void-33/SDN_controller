import argparse
import csv
import os
import time

import requests

from dqn.env import DEST_MAC, SOURCE_MAC, SDNEnvironment


ROUTING_MODES = ("hop", "cost", "dqn")


def parse_args():
    parser = argparse.ArgumentParser(description="Compare RTT for hop, cost, and DQN routing on Torus(3,3).")
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--output", default=os.path.join("results", "rtt_comparison.csv"))
    parser.add_argument("--api-base", default="http://127.0.0.1:8000/api")
    parser.add_argument("--congestion-flows", type=int, default=3)
    parser.add_argument("--congestion-bandwidths", default="20M,40M,80M,100M")
    parser.add_argument("--congestion-duration", type=int, default=45)
    parser.add_argument("--stats-warmup", type=float, default=6.0)
    parser.add_argument("--ping-count", type=int, default=5)
    parser.add_argument("--ping-interval", type=float, default=0.2)
    return parser.parse_args()


def main():
    args = parse_args()
    bandwidths = [item.strip() for item in args.congestion_bandwidths.split(",") if item.strip()]
    env = SDNEnvironment(api_base=args.api_base)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    try:
        env.reset()
        set_routing_mode(args.api_base, "cost")
        env.prime_host_learning()

        with open(args.output, "w", newline="") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["iteration", "hop_avg_rtt_ms", "cost_avg_rtt_ms", "dqn_avg_rtt_ms"],
            )
            writer.writeheader()

            for iteration in range(1, args.iterations + 1):
                set_routing_mode(args.api_base, "cost")
                env.close_congestion()
                congestion = env.make_congestion(
                    duration_seconds=args.congestion_duration,
                    flow_count=args.congestion_flows,
                    bandwidth_choices=bandwidths,
                    randomize=True,
                    cleanup_existing=True,
                )
                time.sleep(args.stats_warmup)

                row = {"iteration": iteration}
                for mode in ROUTING_MODES:
                    set_routing_mode(args.api_base, mode)
                    clear_forward_flow(args.api_base)
                    avg_rtt = ping_avg_rtt(env, args.ping_count, args.ping_interval)
                    row[f"{mode}_avg_rtt_ms"] = avg_rtt

                writer.writerow(row)
                csv_file.flush()
                print(f"iteration={iteration:04d} congestion={congestion} row={row}")

        print(f"Saved RTT comparison CSV to {args.output}")
    finally:
        try:
            set_routing_mode(args.api_base, "cost")
        except Exception:
            pass
        env.close_congestion()
        env.stop()


def set_routing_mode(api_base: str, mode: str):
    response = requests.post(f"{api_base.rstrip('/')}/routing-mode", json={"mode": mode}, timeout=10)
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "success":
        raise RuntimeError(f"failed to switch routing mode to {mode}: {data}")
    return data


def clear_forward_flow(api_base: str):
    response = requests.post(
        f"{api_base.rstrip('/')}/clear-flow",
        json={"src_mac": SOURCE_MAC, "dst_mac": DEST_MAC},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "success":
        raise RuntimeError(f"failed to clear forward flow: {data}")
    return data


def ping_avg_rtt(env: SDNEnvironment, count: int, interval: float):
    src = env.net.get("h1x1")
    dst = env.net.get("h3x3")
    output = src.cmd(f"ping -c {count} -i {interval} -q {dst.IP()}")
    avg_rtt, _packet_loss = env._parse_ping(output)
    return avg_rtt


if __name__ == "__main__":
    main()

