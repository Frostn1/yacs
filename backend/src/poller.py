from datetime import timedelta
from requests import post
from requests.exceptions import RequestException
from loguru import logger

from src.collected_data import CollectedData

POLL_PORT = 6612
POLL_URL = "http://{ip_address}:{port}/"
TIMEOUT = timedelta(seconds=10)


def poll_endpoint(ip_address: str) -> CollectedData:
    """
    Poll endpoint PC to collect system data.
    Args:
        ip_address (str): IP address of remote pc
    Raises:
        RequestException
        KeyError
    Returns:
        CollectedData: CollectedData about pc
    """

    try:
        url = POLL_URL.format(ip_address=ip_address, port=POLL_PORT)
        response = post(url, json={"command": "SCAN"}, timeout=TIMEOUT.total_seconds())
        response.raise_for_status()

        return CollectedData(**response.json()["data"])
    except (RequestException, KeyError) as e:
        logger.error(f"[!] Error polling < {ip_address} > : {str(e)}")
        raise
