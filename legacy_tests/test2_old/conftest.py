import pytest
import socket
import ssl
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def sample_ip():
    return "1.2.3.4"

@pytest.fixture
def sample_port():
    return 80

@pytest.fixture
def mock_socket(mocker):
    return mocker.patch('socket.socket')

@pytest.fixture
def sample_packet_bytes():
    # A dummy 64-byte packet
    return b'\x00' * 64

@pytest.fixture
def ja3_profiles():
    return ["chrome_120", "firefox_120", "safari_17"]
