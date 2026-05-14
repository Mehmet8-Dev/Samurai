from ddos_samurai.cli.runtime import _resolve_scenario_backend_attack_vector


def test_scenario_backend_http_defaults_to_http_vector():
    backend, vector = _resolve_scenario_backend_attack_vector("http")
    assert backend == "http"
    assert vector == "http"


def test_scenario_backend_http2_maps_to_http2_vector():
    backend, vector = _resolve_scenario_backend_attack_vector("http2")
    assert backend == "http2"
    assert vector == "http2"


def test_scenario_backend_l4_tcp_maps_to_basic_vector():
    backend, vector = _resolve_scenario_backend_attack_vector("l4_tcp")
    assert backend == "l4_tcp"
    assert vector == "basic"
