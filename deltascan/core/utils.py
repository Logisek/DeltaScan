import hashlib
import json


def n_hosts_on_subnet(subnet):
    """
    Returns the number of hosts on the subnet.
    """
    return 2 ** (32 - int(subnet.split("/")[1]))

def hash_json(json_str):
    """
    Hashes a JSON string using the SHA256 algorithm.
    """
    json_bytes = json_str.encode('utf-8')
    sha256_hash = hashlib.sha256(json_bytes).hexdigest()
    return sha256_hash