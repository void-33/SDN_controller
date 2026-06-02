from web.main import get_metrics


def test_get_metrics_empty():
    response = get_metrics()
    assert "metrics" in response
    assert isinstance(response["metrics"], list)
