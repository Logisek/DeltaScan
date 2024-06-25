from deltascan.core.utils import hash_string
import json

SCANS_FROM_DB_TEST_V1 = [
    {"id": 1, "uuid": "uuid_1", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": [
            {"portid": "80", "protocol": "tcp", "state": {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "protocol": "tcp", "state": {"state": "closed"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "protocol": "tcp", "state": {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
            ]
        }, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 2, "uuid": "uuid_2", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": [
            {"portid": "80", "protocol": "tcp", "state": {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
            ]
        }, "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-02 00:00:00"},
    {"id": 3, "uuid": "uuid_3", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": [
            {"portid": "80", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "protocol": "tcp", "state": {"state": "closed"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
            ]
        }, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-03 00:00:00"}
]

SCANS_FROM_DB_JSON_STRING_TEST_V1 = [
    {"id": 1, "uuid": "uuid_1", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": json.dumps({
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": [
            {"portid": "80", "protocol": "tcp", "state": {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "protocol": "tcp", "state": {"state": "closed"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "protocol": "tcp", "state": {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
            ]
        }), "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 2, "uuid": "uuid_2", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": json.dumps({
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": [
            {"portid": "80", "protocol": "tcp", "state": {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
            ]
        }), "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-02 00:00:00"},
    {"id": 3, "uuid": "uuid_3", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": json.dumps({
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": [
            {"portid": "80", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            {"portid": "22", "protocol": "tcp", "state": {"state": "closed"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
            ]
        }), "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-03 00:00:00"}
]


SCANS_FROM_DB_TEST_V1_PORTS_KEYS = [
    {"id": 1, "uuid": "uuid_1", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": {
            "80": {"portid": "80", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            "22": {"portid": "22", "protocol": "tcp", "state":  {"state": "closed"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            "443": {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},

    {"id": 2, "uuid": "uuid_2", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": {
            "80": {"portid": "80", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            "22": {"portid": "22", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            "443": {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
        }}, "result_hash": "d41d8cd98asw0b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
    {"id": 3, "uuid": "uuid_3", "host_subnet": "0.0.0.0/24", "host": "0.0.0.0", "profile_name": "TEST_V1", "arguments": "-vv", "results": {
        "host": "0.0.0.0", "status": "up", "last_boot": "none", "os": ["unknown"], "osfingerprint": "none", "hops": [
                        "10.0.0.0",
                        "10.0.0.1"], "ports": {
            "80": {"portid": "80", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "http", "servicefp": "s_fp_test", "service_product": "Apache"},
            "22": {"portid": "22", "protocol": "tcp", "state":  {"state": "closed"}, "service_name": "ssh", "servicefp": "s_fp_test", "service_product": "OpenSSH"},
            "443": {"portid": "443", "protocol": "tcp", "state":  {"state": "open"}, "service_name": "https", "servicefp": "s_fp_test", "service_product": "Nginx"}
        }}, "result_hash": "d41d8cd98f00b204e9800998ecf8427e", "created_at": "2021-01-01 00:00:00"},
]


def mock_data_with_real_hash(test_data):
    for scan in test_data:
        scan["result_hash"] = hash_string(json.dumps(scan["results"]))
    return test_data


DIFFS = [
    {
        "ids": [1, 2],
        "dates": ["2024-02-01 00:00:00", "2024-01-01 00:00:00"],
        "generic": [{
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
            }, {
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
        "ids": [1, 2],
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
                    "120": {
                        "state": {
                            "from": "open",
                            "to": "closed"
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

REPORT_DIFFS = [
    {
        "date_from": "2024-02-01 00:00:00",
        "date_to": "2024-02-06 00:00:00",
        "generic": [{
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
            }, {
                "host": "0.0.0.0",
                "arguments": "-vv",
                "profile_name": "PROFILE_1"
        }],
        "uuids": ["a123456", "a123411"],
        "diffs": {
            "added": [],
            "removed": [],
            "changed": [["osfingerprint", "from", "os_fingerprint_old", "to", "os_fingerprint_new"]]
        }
    },
    {
        "date_from": "2024-02-06 00:00:00",
        "date_to": "2024-02-04 00:00:00",
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
            "added": [["new_data", "of", "any", "type"]],
            "removed": [["status", "good"]],
            "changed": [["ports", "120", "state", "from", "open", "to", "closed"]]
        }
    }
]

SCAN_NMAP_RESULTS = {
    "nmaprun": {
        "hosts": [],
        "args": "-sS",
        "start": "12345678",
        "scaninfo": "Info",
        "runstats": "Stats",
    }
}
SCAN_NMAP_RESULTS["nmaprun"]["host"] = [
       {
            "status": {
                "state": "up"
            },
            "address": [
                {
                "addr": "0.0.0.0",
                "addrtype": "ipv4"
                },
                {
                "addr": "D0:54:54:54:54:A4",
                "addrtype": "mac",
                "vendor": "NetApp"
                }
            ],
            "ports": {
                "port": [
                    {
                        "protocol": "tcp",
                        "portid": "80",
                        "state": {
                            "state": "open",
                            "reason": "syn-ack",
                            "reason_ttl": "64"
                        },
                        "service": {
                            "name": "http",
                            "product": "Apache",
                            "version": "8.1",
                            "extrainfo": "protocol 2.0",
                            "servicefp": "s_fp_test",
                            "method": "probed",
                            "conf": "10",
                            "cpe": "cpe:/a:openbsd:openssh:8.1"
                        },
                    },
                    {
                        "protocol": "tcp",
                        "portid": "22",
                        "state": {
                            "state": "closed",
                            "reason": "syn-ack",
                            "reason_ttl": "64"
                        },
                        "service": {
                            "name": "ssh",
                            "product": "OpenSSH",
                            "version": "8.1",
                            "extrainfo": "protocol 2.0",
                            "servicefp": "s_fp_test",
                            "method": "probed",
                            "conf": "10",
                            "cpe": "cpe:/a:openbsd:openssh:8.1"
                        },
                    },
                    {
                        "protocol": "tcp",
                        "portid": "443",
                        "state": {
                            "state": "open",
                            "reason": "syn-ack",
                            "reason_ttl": "64"
                        },
                        "service": {
                            "name": "https",
                            "product": "Nginx",
                            "version": "8.1",
                            "extrainfo": "protocol 2.0",
                            "servicefp": "s_fp_test",
                            "method": "probed",
                            "conf": "10",
                            "cpe": "cpe:/a:openbsd:openssh:8.1"
                        },
                    }
                ]
            },
            "os": {
                "portused": [
                {
                    "state": "open",
                    "proto": "tcp",
                    "portid": "22"
                },
                {
                    "state": "closed",
                    "proto": "tcp",
                    "portid": "666"
                },
                {
                    "state": "closed",
                    "proto": "udp",
                    "portid": "43268"
                }
                ],
                "osmatch": [
                    {
                        "name": "FreeBSD 43.0-RELEASE - 43.0-CURRENT",
                        "accuracy": "99",
                        "line": "26734",
                        "osclass": [
                            {
                                "type": "general purpose",
                                "vendor": "FreeBSD",
                                "osfamily": "FreeBSD",
                                "osgen": "12.X",
                                "accuracy": "93",
                                "cpe": "cpe:/o:xxxxx:freebsd:12"
                            },
                            {
                                "type": "general purpose",
                                "vendor": "FreeBSD",
                                "osfamily": "FreeBSD",
                                "osgen": "13.X",
                                "accuracy": "93",
                                "cpe": "cpe:/o:freebsd:freebsd:13"
                            }
                        ]
                    },
                    {
                        "name": "NAS (FreeBSD 43.0-RELEASE)",
                        "accuracy": "90",
                        "line": "26772",
                        "osclass": {
                        "type": "storage-misc",
                        "vendor": "FreeBSD",
                        "osfamily": "FreeBSD",
                        "osgen": "43.X",
                        "accuracy": "90",
                        "cpe": [
                            "cpe:/a:xxxxx:xxxxxx",
                            "cpe:/o:xxxxxx:xxxxxxxx:12.0"
                        ]
                        }
                    },
                    {
                        "name": "FreeBSD 54.0-RELEASE - 56.0-CURRENT",
                        "accuracy": "90",
                        "line": "26281",
                        "osclass": [
                        {
                            "type": "general purpose",
                            "vendor": "FreeBSD",
                            "osfamily": "FreeBSD",
                            "osgen": "11.X",
                            "accuracy": "90",
                            "cpe": "cpe:/o:xxxxxx:xxxxxxx:11"
                        },
                        {
                            "type": "general purpose",
                            "vendor": "FreeBSD",
                            "osfamily": "FreeBSD",
                            "osgen": "43.X",
                            "accuracy": "90",
                            "cpe": "cpe:/o:xxxxxxx:xxxxxxx:12"
                        }
                        ]
                    },
                    {
                        "name": "FreeBSD 43.2-RELEASE - 65.3 RELEASE or 65.2-STABLE",
                        "accuracy": "90",
                        "line": "26487",
                        "osclass": {
                        "type": "general purpose",
                        "vendor": "FreeBSD",
                        "osfamily": "FreeBSD",
                        "osgen": "11.X",
                        "accuracy": "90",
                        "cpe": "cpe:/o:xxxxxxx:xxxxxx:11"
                        }
                    },
                ]
            },
            "uptime": {
                "seconds": "17",
                "lastboot": "12345678"
            },
            "trace": {
                "hop": [
                    {
                        "ttl": "1",
                        "ipaddr": "10.0.0.1",
                        "rtt": "1.1"
                    },
                    {
                        "ttl": "2",
                        "ipaddr": "10.0.0.2",
                        "rtt": "1.1"
                    }
                ]
            },
       }
]
