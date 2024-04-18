from deltascan.core.utils import hash_string
import json
from dotmap import DotMap

SCANS_FROM_DB_TEST_V1 = [
    {"id": 1, "uuid": "uuid_1", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv" ,"results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["none"], "osfingerprint": "none", "hops": [
                        {"ipaddr": "10.0.0.0", "host": "host_1"},
                        {"ipaddr": "10.0.0.1", "host": "host_2"}],"ports": [
            {"portid": "80", "proto": "tcp", "state": {"state": "open"}, "service": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "proto": "tcp","state": {"state": "closed"}, "service": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "proto": "tcp","state": {"state": "open"}, "service": "https", "servicefp": "s_fp_test", "service_product": "Nginx"} 
            ]
        }, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 2, "uuid": "uuid_2", "host_subnet": "0.0.0.0/24","host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["none"], "osfingerprint": "none", "hops": [
                        {"ipaddr": "10.0.0.0", "host": "host_1"},
                        {"ipaddr": "10.0.0.1", "host": "host_2"}],"ports": [
            {"portid": "80", "proto": "tcp","state": {"state": "open"}, "service": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "proto": "tcp","state":  {"state": "open"}, "service": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "proto": "tcp","state":  {"state": "open"}, "service": "https", "servicefp": "s_fp_test", "service_product": "Nginx"} 
            ]
        }, "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-02 00:00:00"},
    {"id": 3, "uuid": "uuid_3", "host_subnet": "0.0.0.0/24","host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["none"], "osfingerprint": "none", "hops": [
                        {"ipaddr": "10.0.0.0", "host": "host_1"},
                        {"ipaddr": "10.0.0.1", "host": "host_2"}],"ports": [
            {"portid": "80", "proto": "tcp","state":  {"state": "open"}, "service": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "proto": "tcp","state": {"state": "closed"}, "service": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "proto": "tcp","state":  {"state": "open"}, "service": "https", "servicefp": "s_fp_test", "service_product": "Nginx"} 
            ]
        }, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-03 00:00:00"}
]


SCANS_FROM_DB_TEST_V1_PORTS_KEYS = [
    {"id": 1, "uuid": "uuid_1", "host_subnet": "0.0.0.0/24","host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["none"], "osfingerprint": "none", "hops": [
                        {"ipaddr": "10.0.0.0", "host": "host_1"},
                        {"ipaddr": "10.0.0.1", "host": "host_2"}],"ports": {
            "80": {"portid": "80", "proto": "tcp","state":  {"state": "open"}, "service": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            "22": {"portid": "22", "proto": "tcp","state":  {"state": "closed"}, "service": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            "443": {"portid": "443", "proto": "tcp","state":  {"state": "open"}, "service": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},

    {"id": 2, "uuid": "uuid_2", "host_subnet": "0.0.0.0/24","host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["none"], "osfingerprint": "none", "hops": [
                        {"ipaddr": "10.0.0.0", "host": "host_1"},
                        {"ipaddr": "10.0.0.1", "host": "host_2"}],"ports": {
            "80": {"portid": "80", "proto": "tcp","state":  {"state": "open"}, "service": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            "22": {"portid": "22", "proto": "tcp","state":  {"state": "open"}, "service": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            "443": {"portid": "443", "proto": "tcp","state":  {"state": "open"}, "service": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
        }}, "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 3, "uuid": "uuid_3", "host_subnet": "0.0.0.0/24","host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["none"], "osfingerprint": "none", "hops": [
                        {"ipaddr": "10.0.0.0", "host": "host_1"},
                        {"ipaddr": "10.0.0.1", "host": "host_2"}],"ports": {
            "80": {"portid": "80", "proto": "tcp","state":  {"state": "open"}, "service": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            "22": {"portid": "22", "proto": "tcp","state":  {"state": "closed"}, "service": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            "443": {"portid": "443", "proto": "tcp","state":  {"state": "open"}, "service": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
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
        "generic": [{
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
            },{
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
        }],
        "uuids": ["a123456", "a123411"],
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
        "generic": [
            {
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
            },
            {
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
            }
        ],
        "uuids": ["b123456", "b123411"],
        "diffs": {
            "added": {
                "new_data": {
                    "of": {
                        "any": "type"
                    }
                }
            },
            "removed": {
                "status": "good"
            },
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

ARTICULATED_DIFFS = [
    {
        "added": [],
        "changed": [["osfingerprint", "from", "os_fingerprint_old", "to", "os_fingerprint_new"]],
        "removed": []
    },
    {
        "added": [["new_data", "of", "any", "type"]],
        "changed": [["ports", "120", "state", "from", "open", "to", "closed"]],
        "removed": [["status", "good"]]
    }]

SCAN_NMAP_RESULTS = DotMap({"hosts": []})
SCAN_NMAP_RESULTS.hosts = [
    DotMap({
        "address": "0.0.0.0",
        "status": "up",
        "services": [
            DotMap({
                "_portid": 80,
                "_state": "open",
                "_protocol": "tcp",
                "service": "http",
                "servicefp": "s_fp_test",
                "banner": "Apache"
            }),
            DotMap({
                "_portid": 22,
                "_state": "closed",
                "_protocol": "tcp",
                "service": "ssh",
                "servicefp": "s_fp_test",
                "banner": "OpenSSH"
            }),
            DotMap({
                "_portid": 443,
                "_state": "open",
                "_protocol": "tcp",
                "service": "https",
                "servicefp": "s_fp_test",
                "banner": "Nginx"
            })
        ],
        "_extras": DotMap({
                "os": DotMap({
                    "osmatches": [
                        DotMap({
                            "osmatch": DotMap({
                                "name": "os_name"
                            })
                        })
                    ],
                    "osfingerprints": [
                        DotMap({
                            "fingerprint": "os_fingerprint"
                        })
                    ]
                }),
                "trace": DotMap({"hops": [DotMap({"ipaddr": "10.0.0.0", "host": "host_1"}), DotMap({"ipaddr": "10.0.0.1", "host": "host_2"})]}),
                "uptime": DotMap({"lastboot": "12345678"}),
        }),
    })
]
