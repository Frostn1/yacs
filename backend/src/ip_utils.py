import ipaddress
from loguru import logger
from src.utils import is_ipaddress  # Import the existing function

def expand_ips(ip_list):
    """
    Expand a list of IPs, CIDR blocks, and ranges into individual IPs.
    Returns:
        list[str]: List of expanded IPs in string format.
    """
    expanded_ips = set()

    for ip in ip_list:
        if '-' in ip:  # Expand IP range (e.g., "192.168.1.1-192.168.1.10")
            try:
                start_ip, end_ip = map(ipaddress.IPv4Address, ip.split('-'))
                expanded_ips.update(str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1))
            except ValueError:
                logger.error(f"Invalid IP range: {ip}")
                continue

        elif '/' in ip:  # Expand CIDR block (e.g., "192.168.1.0/24")
            try:
                expanded_ips.update(str(ip) for ip in ipaddress.ip_network(ip, strict=False).hosts())
            except ValueError:
                logger.error(f"Invalid CIDR block: {ip}")
                continue

        elif is_ipaddress(ip):  # Single valid IP
            expanded_ips.add(ip)

        else:
            logger.error(f"Invalid IP format: {ip}")

    return list(expanded_ips)  # Ensure all values are strings