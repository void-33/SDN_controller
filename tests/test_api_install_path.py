import handlers
from web.main import ClearFlowRequest, InstallPathRequest, clear_flow, install_selected_path


def test_install_path_records_rl_managed_flow():
    src_mac = bytes.fromhex("000000000101")
    dst_mac = bytes.fromhex("000000000303")
    handlers.mac_to_port["00:00:00:00:00:00:03:03"] = {dst_mac: 1}

    payload = {
        "src_mac": "00:00:00:00:01:01",
        "dst_mac": "00:00:00:00:03:03",
        "path": [["00:00:00:00:00:00:01:01", 2], ["00:00:00:00:00:00:01:02", 3]],
    }

    response = install_selected_path(InstallPathRequest(**payload))

    assert response["status"] == "success"
    flow = handlers.active_flows[(src_mac, dst_mac)]
    assert flow["rl_managed"] is True
    assert flow["dst_dpid"] == "00:00:00:00:00:00:03:03"
    assert flow["routing_mode"] == "api"


def test_clear_flow_removes_active_flow_state():
    src_mac = bytes.fromhex("000000000101")
    dst_mac = bytes.fromhex("000000000303")
    handlers.active_flows[(src_mac, dst_mac)] = {
        "path": [("s1", 1)],
        "dst_dpid": "s2",
        "dst_port": 1,
    }

    response = clear_flow(ClearFlowRequest())

    assert response["status"] == "success"
    assert response["cleared"] is True
    assert (src_mac, dst_mac) not in handlers.active_flows
