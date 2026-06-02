import topology
from web.main import get_k_shortest_paths


def test_k_shortest_paths_no_topology():
    response = get_k_shortest_paths(
        src="00:00:00:00:00:00:01:01",
        dst="00:00:00:00:00:00:03:03",
        k=5,
    )
    assert response == {"paths": []}


def test_k_shortest_paths_orders_by_hop_count():
    topology.add_link("s1", 1, "s2", 1, cost=1)
    topology.add_link("s2", 2, "s3", 1, cost=1)
    topology.add_link("s1", 3, "s3", 3, cost=5)

    response = get_k_shortest_paths(src="s1", dst="s3", k=2)

    assert response["paths"] == [[("s1", 3)], [("s1", 1), ("s2", 2)]]
