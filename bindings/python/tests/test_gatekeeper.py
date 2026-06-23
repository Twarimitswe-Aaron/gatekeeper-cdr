import pytest
import gatekeeper_cdr

def test_sniff_format_payload_too_short():
    with pytest.raises(gatekeeper_cdr.GatekeeperError) as exc_info:
        gatekeeper_cdr.sniff_format(b"short")
    assert "payload too short" in str(exc_info.value).lower()

def test_sniff_format_unknown():
    with pytest.raises(gatekeeper_cdr.GatekeeperError) as exc_info:
        gatekeeper_cdr.sniff_format(b"this_is_a_very_long_but_unknown_format_string_1234")
    assert "unrecognised file magic" in str(exc_info.value).lower()

def test_sniff_format_png():
    # A structurally valid PNG header
    png_sig = b"\x89PNG\r\n\x1a\n"
    chunk_len = b"\x00\x00\x00\x0D"
    chunk_type = b"IHDR"
    valid_png_header = png_sig + chunk_len + chunk_type
    
    fmt = gatekeeper_cdr.sniff_format(valid_png_header)
    assert fmt == "Png"

def test_sniff_format_jpeg():
    # A structurally valid JPEG header
    soi = b"\xFF\xD8"
    app0 = b"\xFF\xE0\x00\x10"
    jfif = b"JFIF\x00\x01\x01\x00"
    eoi = b"\xFF\xD9"
    valid_jpeg_header = soi + app0 + jfif + eoi
    
    fmt = gatekeeper_cdr.sniff_format(valid_jpeg_header)
    assert fmt == "Jpeg"

def test_disarm_invalid_payload():
    with pytest.raises(gatekeeper_cdr.GatekeeperError):
        gatekeeper_cdr.disarm(b"invalid data")
