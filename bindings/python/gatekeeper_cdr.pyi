class GatekeeperError(Exception):
    """Exception raised when Gatekeeper CDR engine encounters an error."""
    pass

def sniff_format(payload: bytes, /) -> str:
    """
    Detect the format of an image/file payload without fully decoding it.
    
    Args:
        payload (bytes): The raw file bytes to inspect.
        
    Returns:
        str: The detected format (e.g. 'Jpeg', 'Png', 'Gif', 'Webp', 'Pdf', 'Office').
        
    Raises:
        GatekeeperError: If the format is unknown or the payload is too short.
    """
    ...

def disarm(payload: bytes, /) -> bytes:
    """
    Disarm and reconstruct a file payload, stripping all metadata and potential exploits.
    
    Args:
        payload (bytes): The raw untrusted file bytes.
        
    Returns:
        bytes: A sanitized, re-encoded file output that shares zero bytes with the original.
        
    Raises:
        GatekeeperError: If the payload is invalid, corrupt, or exceeds limits.
    """
    ...
