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

import unittest
from unittest.mock import MagicMock, patch
from .test_data.mock_data import (SCAN_NMAP_RESULTS)
from deltascan.core.scanner import Scanner
import json


class TestScanner(unittest.TestCase):
    @patch("deltascan.core.scanner.Parser.extract_port_scan_dict_results")
    @patch("deltascan.core.scanner.LibNmapWrapper.scan")
    def test_scan_calls(self, mock_nmap, mock_extract_port_scan_dict_results):
        self._scanner = Scanner
        self._scanner.scan("0.0.0.0", "-vv")
        mock_extract_port_scan_dict_results.assert_called_once()
        mock_nmap.assert_called_once()

    @patch("deltascan.core.parser.xmltodict", MagicMock())
    def test_scan(self):
        with patch("deltascan.core.scanner.LibNmapWrapper.scan", MagicMock()):
            with patch("deltascan.core.parser.replace_nested_keys", MagicMock(return_value=SCAN_NMAP_RESULTS)):
                self._scanner = Scanner()
                results = self._scanner.scan("0.0.0.0", "-sV")
                print(json.dumps(results, indent=3))
                self.assertEqual(results, {
                    "args": "-sS",
                    "scaninfo": "Info",
                    "start": "12345678",
                    "runstats": "Stats",
                    "results": [
                        {
                            "host": "0.0.0.0",
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
                            "status": "up",
                            "ports": [
                                {
                                    "portid": "80",
                                    "protocol": "tcp",
                                    "state": {
                                        "state": "open",
                                        "reason": "syn-ack",
                                        "reason_ttl": "64"
                                    },
                                    "service_name": "http",
                                    "servicefp": "s_fp_test",
                                    "service_product": "Apache",
                                    "service": {
                                        "name": "http",
                                        "product": "Apache",
                                        "version": "8.1",
                                        "extrainfo": "protocol 2.0",
                                        "servicefp": "s_fp_test",
                                        "method": "probed",
                                        "conf": "10",
                                        "cpe": "cpe:/a:openbsd:openssh:8.1"
                                    }
                                },
                                {
                                    "portid": "22",
                                    "protocol": "tcp",
                                    "state": {
                                        "state": "closed",
                                        "reason": "syn-ack",
                                        "reason_ttl": "64"
                                    },
                                    "service_name": "ssh",
                                    "servicefp": "s_fp_test",
                                    "service_product": "OpenSSH",
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
                                    "portid": "443",
                                    "protocol": "tcp",
                                    "state": {
                                        "state": "open",
                                        "reason": "syn-ack",
                                        "reason_ttl": "64"
                                    },
                                    "service_name": "https",
                                    "servicefp": "s_fp_test",
                                    "service_product": "Nginx",
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
                            ],
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
                            "os": [
                                "FreeBSD 43.0-RELEASE - 43.0-CURRENT",
                                "NAS (FreeBSD 43.0-RELEASE)",
                                "FreeBSD 54.0-RELEASE - 56.0-CURRENT"
                            ],
                            "hops": [
                                "10.0.0.1",
                                "10.0.0.2"
                            ],
                            "osfingerprint": "none",
                            "last_boot": "12345678"
                            }
                        ]
                    }
                )
