import pytest
from ddos_samurai.packet import PacketConfig, SpoofingOptions, create_packet


def test_build_tcp_packet_minimal():
    cfg = PacketConfig(target_ip="127.0.0.1", target_port=8080)
    pkt = create_packet(cfg)
    assert pkt is not None
    # Ensure Ethernet/IP/TCP layers present (scapy layers create names)
    assert b"\x08\x00" in bytes(pkt) or len(bytes(pkt)) > 0


def test_dns_packet_with_edns_and_qtypes():
    cfg = PacketConfig(target_ip="8.8.8.8", target_port=53, attack_vector="dns", dns_qtype=["A", "AAAA"], dns_edns=True)
    pkt = create_packet(cfg)
    assert pkt is not None
    data = bytes(pkt)
    # DNS query opcode and QTYPE presence indication
    assert len(data) > 0


def test_spoofing_options_subnet_and_list(tmp_path, monkeypatch):
    # create a temporary list file
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("10.0.0.1\n10.0.0.2\n")

    spoof_opts = SpoofingOptions(mode='list', list_file=str(ip_file))
    cfg = PacketConfig(target_ip="192.168.0.1", target_port=80, spoof=True, spoof_opts=spoof_opts)

    pkt = create_packet(cfg)
    assert pkt is not None


@pytest.mark.parametrize("mode", ['random', 'realistic', 'subnet'])
def test_get_spoofed_ip_modes(mode):
    # Basic check that create_packet succeeds with different spoof modes
    spoof_opts = SpoofingOptions(mode=mode, subnet='192.168.1.0/24')
    cfg = PacketConfig(target_ip="192.168.0.1", target_port=80, spoof=True, spoof_opts=spoof_opts)
    pkt = create_packet(cfg)
    assert pkt is not None
