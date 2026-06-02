from dqn.env import (
    CONGESTION_HOSTS,
    DEST_DPID,
    DEST_HOST,
    DEST_MAC,
    SOURCE_DPID,
    SOURCE_HOST,
    SOURCE_MAC,
    SDNEnvironment,
)


def test_fixed_training_endpoints_match_plan():
    assert SOURCE_HOST == "h1x1"
    assert DEST_HOST == "h3x3"
    assert SOURCE_DPID == "00:00:00:00:00:00:01:01"
    assert DEST_DPID == "00:00:00:00:00:00:03:03"
    assert SOURCE_MAC == "00:00:00:00:01:01"
    assert DEST_MAC == "00:00:00:00:03:03"


def test_parse_ping_summary():
    output = """
    5 packets transmitted, 5 received, 0% packet loss, time 801ms
    rtt min/avg/max/mdev = 0.057/0.082/0.098/0.015 ms
    """
    avg_rtt, packet_loss = SDNEnvironment._parse_ping(output)
    assert avg_rtt == 0.082
    assert packet_loss == 0.0


def test_congestion_hosts_exclude_training_endpoints():
    assert SOURCE_HOST not in CONGESTION_HOSTS
    assert DEST_HOST not in CONGESTION_HOSTS
    assert len(CONGESTION_HOSTS) == 7
