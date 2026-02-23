from ddos_samurai.stealth import create_smuggled_request, apply_evasion


def test_create_smuggled_request_cl_te():
    """Tests CL.TE smuggling request creation."""
    req = create_smuggled_request("testhost.com", 80, "CL.TE")
    assert b"Content-Length:" in req
    assert b"Transfer-Encoding: chunked" in req
    assert b"GET /404-not-found" in req

def test_create_smuggled_request_te_cl():
    """Tests TE.CL smuggling request creation."""
    req = create_smuggled_request("testhost.com", 80, "TE.CL")
    assert b"Content-Length: 4" in req
    assert b"Transfer-Encoding: chunked" in req
    assert b"GET /404-not-found" in req

def test_apply_evasion():
    """Tests that evasion techniques modify the payload."""
    payload = "select * from users"
    
    # Case evasion
    evaded_payload_case = apply_evasion(payload, ["case"])
    assert evaded_payload_case != payload
    assert "SELECT" in evaded_payload_case.upper()

    # URL encoding evasion
    evaded_payload_url = apply_evasion(payload, ["url"])
    assert evaded_payload_url != payload
    assert "%" in evaded_payload_url

    # Comment evasion
    evaded_payload_comment = apply_evasion(payload, ["comment"])
    assert evaded_payload_comment != payload
    assert "/*" in evaded_payload_comment and "*/" in evaded_payload_comment
