import os

import pytest

import routing
import topology
from web.main import RoutingModeUpdate, get_routing_mode, update_routing_mode


def reset_topology():
    with topology._lock:
        topology.links.clear()
        topology.port_map.clear()
        topology.port_speeds.clear()


def test_route_selector_hop_ignores_dynamic_cost():
    reset_topology()
    topology.add_link("s1", 1, "s2", 1, cost=100)
    topology.add_link("s1", 2, "s3", 1, cost=1)
    topology.add_link("s3", 3, "s2", 2, cost=1)

    routing.set_mode("hop")
    decision = routing.select_path("s1", "s2")

    assert decision.routing_mode == "hop"
    assert decision.path == [("s1", 1)]


def test_route_selector_cost_uses_dijkstra_cost():
    reset_topology()
    topology.add_link("s1", 1, "s2", 1, cost=100)
    topology.add_link("s1", 2, "s3", 1, cost=1)
    topology.add_link("s3", 3, "s2", 2, cost=1)

    routing.set_mode("cost")
    decision = routing.select_path("s1", "s2")

    assert decision.routing_mode == "cost"
    assert decision.path == [("s1", 2), ("s3", 3)]


def test_routing_mode_api_rejects_invalid_mode():
    routing.set_mode("cost")

    response = update_routing_mode(RoutingModeUpdate(mode="invalid"))

    assert response["status"] == "error"
    assert response["mode"] == "cost"


def test_routing_mode_api_rejects_missing_dqn_model(monkeypatch):
    routing.set_mode("cost")
    monkeypatch.setattr(routing, "DQN_MODEL_PATH", os.path.join("dqn", "missing-model.pth"))
    monkeypatch.setattr(routing, "_dqn_policy", None)

    response = update_routing_mode(RoutingModeUpdate(mode="dqn"))

    assert response["status"] == "error"
    assert response["mode"] == "cost"
    assert "not found" in response["message"]


def test_get_routing_mode_shape():
    response = get_routing_mode()

    assert "mode" in response
    assert response["valid_modes"] == ["cost", "dqn", "hop"]
    assert "dqn_available" in response


def test_dqn_policy_maps_best_available_action(monkeypatch, tmp_path):
    torch = pytest.importorskip("torch")

    from dqn.agent import DQN
    from dqn.inference import DQNPathPolicy

    reset_topology()
    topology.add_link(routing.SOURCE_DPID, 1, "a", 1, cost=1)
    topology.add_link("a", 2, routing.DEST_DPID, 1, cost=1)
    topology.add_link(routing.SOURCE_DPID, 3, "b", 1, cost=1)
    topology.add_link("b", 4, routing.DEST_DPID, 1, cost=1)

    model = DQN(108, 5)
    for param in model.parameters():
        param.data.zero_()
    model.layers[-1].bias.data[1] = 10.0

    model_path = tmp_path / "model.pth"
    torch.save({"policy_state_dict": model.state_dict()}, model_path)

    policy = DQNPathPolicy(str(model_path))
    action, path = policy.select_action_path(routing.SOURCE_DPID, routing.DEST_DPID)

    assert action == 1
    assert path == [(routing.SOURCE_DPID, 3), ("b", 4)]

