import hashlib
from datetime import datetime
from deltascan.core.config import APP_DATE_FORMAT
import re
import os

def n_hosts_on_subnet(subnet: str) -> int:
    """
    Returns the number of hosts on the subnet.
    """
    return 2 ** (32 - int(subnet.split("/")[1]))

def hash_string(json_str: str) -> str:
    """
    Hashes a JSON string using the SHA256 algorithm.
    """
    json_bytes = json_str.encode('utf-8')
    sha256_hash = hashlib.sha256(json_bytes).hexdigest()
    return sha256_hash

def datetime_validation(date: str) -> bool:
    """
    Validate if a given date string is in the format '%Y%m%d %H:%M:%S'.

    Args:
        date (str): The date string to be validated.

    Returns:
        bool: True if the date string is in the correct format, False otherwise.
    """
    try:
        datetime.strptime(date, APP_DATE_FORMAT)
    except ValueError:
        return False
    else:
        return True

def validate_host(value: str) -> bool:
    """
    Validates the given host value.

    Args:
        value (str): The host value to be validated.

    Returns:
        bool or str: Returns True if the host is valid. Otherwise, returns an error message.

    Raises:
        DScanInputValidationException: If an exception occurs during the validation process.
    """
    if not re.match(r"^[a-zA-Z0-9.-/]+$", value):
        return False
    return True

def check_root_permissions():
    """
    Checks if the program is running with root permissions.
    """
    if os.getuid() != 0:
        raise PermissionError("You need root permissions to run this program.")


def find_ports_from_state(ports, state):
    """
    Finds and returns a list of ports with a specific state.

    Args:
        ports (list): A list of dictionaries representing ports.
        state (str): The state to filter ports by.

    Returns:
        list: A list of dictionaries representing ports with the specified state.
    """
    ports_with_state = []
    for p in ports:
        if re.match(state, p["state"]):
            ports_with_state.append(p)
    return ports_with_state

def validate_port_state_type(port_status_type):
    """
    Validates the given port status type.

    Args:
        status_type (str): The port status type to be validated.

    Returns:
        bool or str: Returns True if the port status type is valid. Otherwise, returns an error message.

    Raises:
        DScanInputValidationException: If an exception occurs during the validation process.
    """
    if not all(item in ["open", "closed", "filtered", "all"] for item in port_status_type):
        return False
    return True
