# Clearing mininet configuration
sudo mn -c

# Launching model with specified path mode
SDN_ROUTING_MODE=cost SDN_DQN_MODEL=dqn/dqn_model.pth uvicorn web.main:app --host 127.0.0.1 --port 8000

# Initializing torus network with mininet
sudo mn --controller remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13 --topo torus,3,3

# Benchmarking
sudo -E python -m dqn.benchmark_rtt \
  --iterations 50 \
  --congestion-flows 3 \
  --congestion-bandwidths 20M,40M,80M,100M \
  --output results/rtt_comparison.csv

# Inference
h2x2 iperf -s -u &
h3x1 iperf -s -u &
h1x3 iperf -s -u &
h1x1 ping h3x2
h2x2 iperf -c h1x2 -u -b 100M -t 60 &
h3x1 iperf -c h2x1 -u -b 100M -t 60 &
h1x3 iperf -c h2x3 -u -b 100M -t 60 &