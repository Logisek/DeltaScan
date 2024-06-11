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
from dotmap import DotMap

import copy


class TestScanner(unittest.TestCase):

    @patch("deltascan.core.scanner.Parser.extract_port_scan_dict_results")
    @patch("deltascan.core.scanner.LibNmapWrapper.scan")
    def test_scan_calls(self, mock_nmap, mock_extract_port_scan_dict_results):
        self._scanner = Scanner
        self._scanner.scan("0.0.0.0", "-vv")
        mock_extract_port_scan_dict_results.assert_called_once()
        mock_nmap.assert_called_once()

    def test_scan(self):
        with patch("deltascan.core.scanner.LibNmapWrapper.scan", MagicMock(return_value=SCAN_NMAP_RESULTS)):
            self._scanner = Scanner()
            results = self._scanner.scan("0.0.0.0", "-sV")
            self.assertEqual(results, [
                {
                    "host": "0.0.0.0",
                    "status": "up",
                    "ports": [
                        {
                            "portid": "80",
                            "proto": "tcp",
                            "state": "open",
                            "service": "http",
                            "servicefp": "s_fp_test",
                            "service_product": "Apache"
                        },
                        {
                            "portid": "22",
                            "proto": "tcp",
                            "state": "closed",
                            "service": "ssh",
                            "servicefp": "s_fp_test",
                            "service_product": "OpenSSH"
                        },
                        {
                            "portid": "443",
                            "proto": "tcp",
                            "state": "open",
                            "service": "https",
                            "servicefp": "s_fp_test",
                            "service_product": "Nginx"
                        }
                    ],
                    "os": {
                        "1": "os_name"
                    },
                    "hops": {
                        "1": "10.0.0.0",
                        "2": "10.0.0.1"
                    },
                    "osfingerprint": "os_fingerprint",
                    "last_boot": "12345678"
                }
            ])

        SCAN_NMAP_RESULTS_MISSING = copy.deepcopy(SCAN_NMAP_RESULTS)
        SCAN_NMAP_RESULTS_MISSING.hosts[0].services[0].banner = ""
        with patch("deltascan.core.scanner.LibNmapWrapper.scan", MagicMock(return_value=SCAN_NMAP_RESULTS_MISSING)):
            self._scanner = Scanner()
            results = self._scanner.scan("0.0.0.0", "-sV")
            self.assertEqual(results, [
                {
                    "host": "0.0.0.0",
                    "status": "up",
                    "ports": [
                        {
                            "portid": "80",
                            "proto": "tcp",
                            "state": "open",
                            "service": "http",
                            "servicefp": "s_fp_test",
                            "service_product": "none"
                        },
                        {
                            "portid": "22",
                            "proto": "tcp",
                            "state": "closed",
                            "service": "ssh",
                            "servicefp": "s_fp_test",
                            "service_product": "OpenSSH"
                        },
                        {
                            "portid": "443",
                            "proto": "tcp",
                            "state": "open",
                            "service": "https",
                            "servicefp": "s_fp_test",
                            "service_product": "Nginx"
                        }
                    ],
                    "os": {
                        "1": "os_name"
                    },
                    "hops": {
                        "1": "10.0.0.0",
                        "2": "10.0.0.1"
                    },
                    "osfingerprint": "os_fingerprint",
                    "last_boot": "12345678"
                }
            ])

        SCAN_NMAP_RESULTS_MISSING = copy.deepcopy(SCAN_NMAP_RESULTS)
        SCAN_NMAP_RESULTS_MISSING.hosts[0]._extras.os.osmatches = []
        SCAN_NMAP_RESULTS_MISSING.hosts[0]._extras.os.osmatches.append(DotMap({"osmatch": DotMap({"name": "os_1"})}))
        SCAN_NMAP_RESULTS_MISSING.hosts[0]._extras.os.osmatches.append(DotMap({"osmatch": DotMap({"name": "os_2"})}))
        SCAN_NMAP_RESULTS_MISSING.hosts[0]._extras.os.osmatches.append(DotMap({"osmatch": DotMap({"name": "os_3"})}))
        SCAN_NMAP_RESULTS_MISSING.hosts[0]._extras.os.osmatches.append(DotMap({"osmatch": DotMap({"name": "os_4"})}))

        with patch("deltascan.core.scanner.LibNmapWrapper.scan", MagicMock(return_value=SCAN_NMAP_RESULTS_MISSING)):
            self._scanner = Scanner()
            results = self._scanner.scan("0.0.0.0", "-sV")
            self.assertEqual(results, [
                {
                    "host": "0.0.0.0",
                    "status": "up",
                    "ports": [
                        {
                            "portid": "80",
                            "proto": "tcp",
                            "state": "open",
                            "service": "http",
                            "servicefp": "s_fp_test",
                            "service_product": "Apache"
                        },
                        {
                            "portid": "22",
                            "proto": "tcp",
                            "state": "closed",
                            "service": "ssh",
                            "servicefp": "s_fp_test",
                            "service_product": "OpenSSH"
                        },
                        {
                            "portid": "443",
                            "proto": "tcp",
                            "state": "open",
                            "service": "https",
                            "servicefp": "s_fp_test",
                            "service_product": "Nginx"
                        }
                    ],
                    "os": {
                        "1": "os_1",
                        "2": "os_2",
                        "3": "os_3"
                    },
                    "hops": {
                        "1": "10.0.0.0",
                        "2": "10.0.0.1"
                    },
                    "osfingerprint": "os_fingerprint",
                    "last_boot": "12345678"
                }
            ])
