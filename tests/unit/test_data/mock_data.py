from deltascan.core.utils import hash_string
import json

SCANS_FROM_DB_TEST_V1 = [
    {"id": 1, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": [
            {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            {"portid": "22", "state": "closed", "service": "ssh", "serviceProduct": "OpenSSH"},
            {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"} 
            ]
        }, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 2, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": [
            {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            {"portid": "22", "state": "open", "service": "ssh", "serviceProduct": "OpenSSH"},
            {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"} 
            ]
        }, "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-02 00:00:00"},
    {"id": 3, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": [
            {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            {"portid": "22", "state": "closed", "service": "ssh", "serviceProduct": "OpenSSH"},
            {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"} 
            ]
        }, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-03 00:00:00"}
]


SCANS_FROM_DB_TEST_V1_PORTS_KEYS = [
    {"id": 1, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": {
            "80": {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            "22": {"portid": "22", "state": "closed", "service": "ssh", "serviceProduct": "OpenSSH"},
            "443": {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},

    {"id": 2, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": {
            "80": {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            "22": {"portid": "22", "state": "open", "service": "ssh", "serviceProduct": "OpenSSH"},
            "443": {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
        }}, "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 3, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": {
            "80": {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            "22": {"portid": "22", "state": "closed", "service": "ssh", "serviceProduct": "OpenSSH"},
            "443": {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
]

SCANS_FROM_DB_TEST_V2 = [
    {"id": 1, "host": "10.0.0.0", "profile_name": "TEST_V2", "results": {
        "host": "10.0.0.0", "status": "up", "ports": [
            {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"}
            ]}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 2, "host": "10.0.0.0", "profile_name": "TEST_V2", "results": {
        "host": "10.0.0.0", "status": "up", "ports": [
            {"portid": "22", "state": "closed", "service": "ssh", "serviceProduct": "OpenSSH"}
            ]}, "result_hash": "d41d432d98f0wer04e9800998ecf8427e", "created_at": "2021-01-02 00:00:00"},
    {"id": 3, "host": "10.0.0.0", "profile_name": "TEST_V2", "results": {
        "host": "10.0.0.0", "status": "up", "ports": [
            {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
            ]}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-03 00:00:00"}
]

SCANS_FROM_DB_TEST_V2_PORTS_KEYS = [
    {"id": 1, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": {
            "80": {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            "22": {"portid": "22", "state": "open", "service": "ssh", "serviceProduct": "OpenSSH"},
            "443": {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},

    {"id": 2, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": {
            "80": {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            "22": {"portid": "22", "state": "closed", "service": "ssh", "serviceProduct": "OpenSSH"},
            "443": {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
        }}, "result_hash": "d41d432d98f0wer04e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 3, "host": "0.0.0.0", "profile_name": "TEST_V1", "results": {
        "host": "0.0.0.0", "status": "up", "ports": {
            "80": {"portid": "80", "state": "open", "service": "http", "serviceProduct": "Apache"},
            "22": {"portid": "22", "state": "open", "service": "ssh", "serviceProduct": "OpenSSH"},
            "443": {"portid": "443", "state": "open", "service": "https", "serviceProduct": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
]

def mock_data_with_real_hash(test_data):
    for scan in test_data:
        scan["result_hash"] = hash_string(json.dumps(scan["results"]))
    return test_data

DIFFS = [
    {
        "ids": [1,2],
        "dates": ["2024-02-01 00:00:00", "2024-01-01 00:00:00"],
        "diffs": {
            "added": {},
            "removed": {},
            "changed": {
                "osfingerprint": {
                    "from": "os_fingerprint_old",
                    "to": "os_fingerprint_new"
                }
            }
        },
        "result_hashes": ["a123456", "a123411"]
    },
    {
        "ids": [1,2],
        "dates": ["2024-02-06 00:00:00", "2024-02-04 00:00:00"],
        "diffs": {
            "added": {},
            "removed": {},
            "changed": {
                "ports": {
                    "added": {},
                    "removed": {},
                    "changed": {
                        "120": {
                            "added": {},
                            "removed": {},
                            "changed": {
                                "state": {
                                    "from": "open",
                                    "to": "closed"
                                }
                            
                            }
                        }
                    }
                }
            }
        },
        "result_hashes": ["b123456", "b123411"]
    }
]