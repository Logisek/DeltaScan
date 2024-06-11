# DeltaScan - Network scanning tool 
#     Copyright (C) 2024 Logisek
# 
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>

import hashlib
from datetime import datetime
from deltascan.core.config import (APP_DATE_FORMAT)
import threading
import re
import os


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
    if date is None:
        return False
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


def nmap_arguments_to_list(arguments):
    """
    Converts the given Nmap arguments string to a list of arguments.

    Args:
        arguments (str): The Nmap arguments string.

    Returns:
        list: A list of Nmap arguments.

    """
    _arguments = re.sub(r'-oA.*?(?=-)', '', arguments)

    if _arguments == arguments:
        _arguments = arguments.split("-oA")[0]

    _arguments = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '', _arguments)
    _arguments = _arguments.replace("nmap", "")
    _arguments = [_arg for _arg in _arguments.split(" ") if _arg != "" and _arg != " "]

    return _arguments


class ThreadWithException(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

    def run(self):
        """
        Executes the run method of the parent class and handles any exceptions that occur.

        Raises:
            Exception: If an exception occurs during the execution of the parent class's run method.
        """
        self.exception = None
        try:
            super().run()
        except Exception as e:
            self.exception = e
    
    def start(self):
        """
        Starts the thread and raises any exception that occurred during the thread's execution.

        Raises:
            Exception: If an exception occurred during the thread's execution.
        """
        threading.Thread.start(self)
        if self.exception:
            raise self.exception

    def join(self):
        """
        Wait for the thread to complete.

        This method blocks the calling thread until the thread whose `join` method is called terminates.
        If an exception occurred during the execution of the thread, it will be raised after the thread has terminated.
        """
        threading.Thread.join(self)
        if self.exception:
            raise self.exception
