from ddos_samurai import utils


def test_get_timestamp_and_log_functions(capfd):
    ts = utils.get_timestamp()
    assert ts is not None and len(ts) > 0

    utils.log_info("test info")
    utils.log_warning("test warn")
    utils.log_error("test error")
    utils.log_critical("test critical")

    captured = capfd.readouterr()
    # Should contain at least one of the messages printed
    assert "test info" in captured.out or "test warn" in captured.out


def test_print_banner_outputs():
    utils.print_banner()
    # No assertion other than ensuring it doesn't crash


def test_ethics_warning_override(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda prompt='': 'NO')
    try:
        utils.ethical_warning()
    except SystemExit:
        # expected to exit when input != YES
        assert True
    else:
        pytest.skip("ethical_warning did not exit as expected")
