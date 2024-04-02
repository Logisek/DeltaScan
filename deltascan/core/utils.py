import hashlib
from datetime import datetime
from deltascan.core.config import (
    APP_DATE_FORMAT,
    ADDED,
    CHANGED,
    REMOVED)
from deltascan.core.schemas import Diffs
from deltascan.core.exceptions import DScanResultsSchemaException
from marshmallow  import ValidationError

import re
import os
import copy

def n_hosts_on_subnet(subnet: str) -> int:
    """
    Returns the number of hosts on the subnet.
    """
    if "/" not in subnet:
        return 1
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

def diffs_to_output_format(diffs):
    """
    Convert the given diffs to a specific output format.

    Args:
        diffs (dict): The diffs to be converted.

    Returns:
        dict: The converted diffs in the specified output format.

    Raises:
        DScanResultsSchemaException: If the diffs have an invalid schema.
    """
    try:
        Diffs().load(diffs)
    except (KeyError, ValidationError) as e:
        raise DScanResultsSchemaException(f"Invalid diff results schema: {str(e)}")

    # Here, entity can be many things. In the future an entity, besides port
    # can be a service, a host, the osfingerpint.
    articulated_diffs = {
        ADDED: [],
        CHANGED: [],
        REMOVED: [],
    }

    articulated_diffs[ADDED] = _dict_diff_handler(diffs["diffs"], [], ADDED)
    articulated_diffs[CHANGED] = _dict_diff_handler(diffs["diffs"], [], CHANGED)
    articulated_diffs[REMOVED] = _dict_diff_handler(diffs["diffs"], [], REMOVED)

    return articulated_diffs

def _dict_diff_handler(diff, depth: list, diff_type=CHANGED):
    """
    Handles the dictionary diff.

    Args:
        diff (dict): The dictionary diff to be handled.

    Returns:
        dict: The handled dictionary diff.
    """
    handled_diff = []
    if (CHANGED in diff or ADDED in diff or REMOVED in diff) and isinstance(diff, dict):
        handled_diff.extend(_dict_diff_handler(diff[diff_type], depth, diff_type))
    else:
        for k, v in diff.items():
            tmpd = copy.deepcopy(depth)
            tmpd.append(k)

            if ("to" in v or "from" in v) and isinstance(v, dict):
                tmpd.extend(["from",v["from"],"to", v["to"]])
                handled_diff.append(tmpd)
            elif isinstance(v, dict):
                handled_diff.extend(_dict_diff_handler(v,tmpd,diff_type))
            else:
                tmpd.append(v)
                handled_diff.append(tmpd)
    return handled_diff

def format_string(string: str) -> str:
    """
    Formats a string by making the first letter uppercase and replacing underscores with white spaces.

    Args:
        string (str): The string to be formatted.

    Returns:
        str: The formatted string.
    """
    formatted_string = string.capitalize().replace("_", " ")
    return formatted_string
