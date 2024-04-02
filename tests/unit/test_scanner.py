import unittest
from unittest.mock import MagicMock, patch
from .test_data.mock_data import (SCAN_NMAP_RESULTS)
import json
from deltascan.core.scanner import Scanner 
from dotmap import DotMap

import copy

class TestScanner(unittest.TestCase):

    def test_scan_success(self):
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
                            "state": "open",
                            "service": "http",
                            "servicefp": "s_fp_test",
                            "service_product": "Apache"
                        },
                        {
                            "portid": "22",
                            "state": "closed",
                            "service": "ssh",
                            "servicefp": "s_fp_test",
                            "service_product": "OpenSSH"
                        },
                        {
                            "portid": "443",
                            "state": "open",
                            "service": "https",
                            "servicefp": "s_fp_test",
                            "service_product": "Nginx"
                        }
                    ],
                    "os": [
                        "os_name"
                    ],
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
                            "state": "open",
                            "service": "http",
                            "servicefp": "s_fp_test",
                            "service_product": "none"
                        },
                        {
                            "portid": "22",
                            "state": "closed",
                            "service": "ssh",
                            "servicefp": "s_fp_test",
                            "service_product": "OpenSSH"
                        },
                        {
                            "portid": "443",
                            "state": "open",
                            "service": "https",
                            "servicefp": "s_fp_test",
                            "service_product": "Nginx"
                        }
                    ],
                    "os": [
                        "os_name"
                    ],
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
                            "state": "open",
                            "service": "http",
                            "servicefp": "s_fp_test",
                            "service_product": "Apache"
                        },
                        {
                            "portid": "22",
                            "state": "closed",
                            "service": "ssh",
                            "servicefp": "s_fp_test",
                            "service_product": "OpenSSH"
                        },
                        {
                            "portid": "443",
                            "state": "open",
                            "service": "https",
                            "servicefp": "s_fp_test",
                            "service_product": "Nginx"
                        }
                    ],
                    "os": [
                        "os_1", "os_2", "os_3"
                    ],
                    "osfingerprint": "os_fingerprint",
                    "last_boot": "12345678"
                }
            ])            
