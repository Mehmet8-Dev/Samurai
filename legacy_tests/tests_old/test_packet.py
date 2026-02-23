import pytest
import asyncio
from unittest.mock import patch
from scapy.all import IP, UDP, Ether
from ddos_samurai.packet import PacketConfig, SpoofingOptions, create_packet, get_spoofed_ip
from ddos_samurai.senders import send_packet_async


@pytest.mark.asyncio
async def test_send_packet_async_error_handling():
    """Tests that send_packet_async correctly handles exceptions from sendp."""
    pkt = IP(dst="1.2.3.4") / UDP()
    loop = asyncio.get_event_loop()

    with patch('scapy.all.sendp', side_effect=Exception("Mocked send error")):
        # We need to import the function here to use the patched version
        from ddos_samurai.senders import send_packet_async
        result = await send_packet_async(pkt, True, 1, loop, "udp")
        assert result is False

def test_create_basic_udp_packet():
    """Tests creation of a simple UDP packet without spoofing."""
    config = PacketConfig(target_ip="1.2.3.4", target_port=80, protocol="udp")
    pkt = create_packet(config)
    assert pkt.haslayer(IP)
    assert pkt.haslayer(UDP)
    assert pkt[IP].dst == "1.2.3.4"
    assert pkt[UDP].dport == 80

def test_create_spoofed_udp_packet():
    """Tests that the spoofed source IP is correctly assigned in the packet."""
    # Mock the get_spoofed_ip function to always return a specific IP
    with patch('ddos_samurai.packet.get_spoofed_ip', return_value="10.20.30.40") as mocked_get_ip:
        spoof_opts = SpoofingOptions(mode='random') # Mode doesn't matter as it's mocked
        config = PacketConfig(
            target_ip="1.2.3.4",
            target_port=80,
            protocol="udp",
            spoof=True,
            spoof_opts=spoof_opts
        )
        pkt = create_packet(config)
        
        # Assert that our mocked function was called
        mocked_get_ip.assert_called_once_with(spoof_opts.mode, {'subnet': spoof_opts.subnet, 'file_path': spoof_opts.list_file})
        
        # Assert that the packet's source IP is the one we returned from the mock
        assert pkt.haslayer(IP)
        assert pkt[IP].src == "10.20.30.40"
        assert pkt[IP].dst == "1.2.3.4"

def test_get_spoofed_ip_from_file(tmp_path):
    """Tests the 'list' mode for get_spoofed_ip using a temporary file."""
    # Create a temporary file with IPs
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.1.1.1\n2.2.2.2\n3.3.3.3")

    # Call the function with the path to the temporary file
    spoof_options = {'file_path': str(ip_file)}
    spoofed_ip = get_spoofed_ip('list', spoof_options)

    # Assert that the returned IP is one of the IPs from the file
    assert spoofed_ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

def test_get_spoofed_ip_modes():
    """Tests the different modes of the get_spoofed_ip function."""
    # Realistic mode (should not raise an error)
    realistic_ip = get_spoofed_ip('realistic', {})
    assert isinstance(realistic_ip, str)

    # Random mode
    random_ip = get_spoofed_ip('random', {})
    assert isinstance(random_ip, str)

    # Subnet mode
    subnet_ip = get_spoofed_ip('subnet', {'subnet': '10.0.0.0/24'})
    assert isinstance(subnet_ip, str)
    assert subnet_ip.startswith("10.0.0.")

    # List mode (requires a file)
    # This is harder to unit test without creating temp files, 
    # but we can test the fallback.
    list_ip = get_spoofed_ip('list', {'file_path': 'non_existent_file.txt'})
    assert isinstance(list_ip, str)