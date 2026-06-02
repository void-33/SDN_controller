import routing


def test_reverse_hops_from_canonical_path(monkeypatch):
    # Canonical path: A --(1)-> B --(2)-> C
    canonical = [
        ("A", 1),
        ("B", 2),
    ]

    # Forward link destinations for each hop out_port
    def fake_get_link_destination(dpid, port):
        if (dpid, port) == ("A", 1):
            return ("B", 10)
        if (dpid, port) == ("B", 2):
            return ("C", 20)
        return None

    def fake_get_all_links():
        return [
            ("A", 1, "B", 10, 0, 1.0),
            ("B", 10, "A", 1, 0, 1.0),
            ("B", 2, "C", 20, 0, 1.0),
            ("C", 20, "B", 2, 0, 1.0),
        ]

    monkeypatch.setattr(
        routing.topology, "get_link_destination", fake_get_link_destination
    )
    monkeypatch.setattr(routing.topology, "get_all_links", fake_get_all_links)

    reversed_hops = routing._reverse_hops(canonical)
    assert reversed_hops == [
        ("C", 20),
        ("B", 10),
    ]
