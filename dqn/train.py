import argparse
import os

from dqn.agent import DQNAgent
from dqn.env import ACTION_DIM, STATE_DIM, SDNEnvironment


def parse_args():
    parser = argparse.ArgumentParser(description="Train a DQN routing agent on a Torus(3,3) SDN topology.")
    parser.add_argument("--episodes", type=int, default=500)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--target-sync", type=int, default=100)
    parser.add_argument("--checkpoint", default=os.path.join("dqn", "dqn_model.pth"))
    parser.add_argument("--api-base", default="http://127.0.0.1:8000/api")
    parser.add_argument("--alpha", type=float, default=1.0)
    parser.add_argument("--beta", type=float, default=1.0)
    parser.add_argument("--congestion-bandwidth", default="10M")
    parser.add_argument(
        "--congestion-bandwidths",
        default="5M,10M,20M,40M",
        help="Comma-separated UDP iperf rates sampled randomly each episode.",
    )
    parser.add_argument("--congestion-flows", type=int, default=1)
    parser.add_argument("--congestion-duration", type=int, default=12)
    parser.add_argument("--congestion-warmup", type=float, default=1.0)
    parser.add_argument("--no-congestion", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    env = SDNEnvironment(api_base=args.api_base, alpha=args.alpha, beta=args.beta)
    agent = DQNAgent(state_dim=STATE_DIM, action_dim=ACTION_DIM)
    congestion_bandwidths = [
        bandwidth.strip()
        for bandwidth in args.congestion_bandwidths.split(",")
        if bandwidth.strip()
    ] or [args.congestion_bandwidth]

    os.makedirs(os.path.dirname(args.checkpoint) or ".", exist_ok=True)

    try:
        state = env.reset()
        paths = env.fetch_paths()
        print(f"Discovered {len(paths)} candidate paths from h1x1 to h3x3.")

        for episode in range(1, args.episodes + 1):
            congestion_info = []
            if not args.no_congestion:
                congestion_info = env.make_congestion(
                    duration_seconds=args.congestion_duration,
                    bandwidth=args.congestion_bandwidth,
                    flow_count=args.congestion_flows,
                    randomize=True,
                    bandwidth_choices=congestion_bandwidths,
                )
                if args.congestion_warmup > 0:
                    import time

                    time.sleep(args.congestion_warmup)

            action = agent.select_action(state)
            next_state, reward, done, info = env.step(action)
            loss = agent.step(state, action, reward, next_state, done, batch_size=args.batch_size)
            state = env.reset() if done else next_state

            loss_text = "warmup" if loss is None else f"{loss:.4f}"
            print(
                f"episode={episode:04d} action={action} reward={reward:.3f} "
                f"loss={loss_text} epsilon={agent.epsilon:.3f} "
                f"congestion={congestion_info} info={info}"
            )

            if episode % args.target_sync == 0:
                agent.update_target_network()
                agent.save(args.checkpoint)
                print(f"Saved checkpoint to {args.checkpoint}")

        agent.save(args.checkpoint)
        print(f"Training complete. Saved checkpoint to {args.checkpoint}")
    except KeyboardInterrupt:
        agent.save(args.checkpoint)
        print(f"Training interrupted. Saved checkpoint to {args.checkpoint}")
    finally:
        env.close_congestion()
        env.stop()


if __name__ == "__main__":
    main()
