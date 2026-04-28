import pytest
from ddos_samurai.licensing.gates import enforce_feature_gates, LicenseGateError
from ddos_samurai.licensing.features import LicenseResult, Tier, get_tier_features

class MockArgs:
    def __init__(self, **kwargs):
        self.attack_vector = 'basic'
        self.compute_backend = 'cpu'
        self.xdp_enable = False
        self.xdp_interface = ''
        self.custom_tcp_mode = 'off'
        self.ninja_mode = False
        self.spoof = False
        self.realistic_spoof = False
        self.spoof_subnet = ''
        self.spoof_list_file = ''
        self.spoof_ip = ''
        self.kpi_gate_profile = 'off'
        self.kpi_hard_fail = False
        self.fault_inject = []
        self.prom_textfile = ''
        self.duration = 30
        self.rps = 50.0
        
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_community_tier_basic_usage():
    args = MockArgs()
    features = get_tier_features(Tier.COMMUNITY)
    lr = LicenseResult(valid=True, tier=Tier.COMMUNITY, features=features)
    
    warnings = enforce_feature_gates(args, lr)
    
    assert len(warnings) == 0

def test_community_tier_blocks_gpu_engine():
    args = MockArgs(compute_backend='cuda')
    features = get_tier_features(Tier.COMMUNITY)
    lr = LicenseResult(valid=True, tier=Tier.COMMUNITY, features=features)
    
    with pytest.raises(LicenseGateError):
        enforce_feature_gates(args, lr)

def test_pro_tier_allows_gpu_engine():
    args = MockArgs(compute_backend='cuda')
    features = get_tier_features(Tier.PRO)
    lr = LicenseResult(valid=True, tier=Tier.PRO, features=features)
    
    warnings = enforce_feature_gates(args, lr)
    assert len(warnings) == 0

def test_pro_tier_blocks_advanced_kpi_gate():
    args = MockArgs(kpi_gate_profile='dedicated_lab')
    features = get_tier_features(Tier.PRO)
    lr = LicenseResult(valid=True, tier=Tier.PRO, features=features)
    
    with pytest.raises(LicenseGateError):
        enforce_feature_gates(args, lr)

def test_enterprise_tier_allows_everything():
    args = MockArgs(
        compute_backend='cuda',
        xdp_enable=True,
        xdp_interface='eth0',
        custom_tcp_mode='accurate',
        ninja_mode=True,
        kpi_gate_profile='dedicated_lab'
    )
    features = get_tier_features(Tier.ENTERPRISE)
    lr = LicenseResult(valid=True, tier=Tier.ENTERPRISE, features=features)
    
    warnings = enforce_feature_gates(args, lr)
    assert len(warnings) == 0
