from dataclasses import dataclass

@dataclass
class ClientInfo:
    """Client information extracted from request."""
    device_info: str
    ip_address: str