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
from deltascan.core.utils import (
    n_hosts_on_subnet,
    hash_string,
    datetime_validation,
    datetime_normalization,
    validate_host,
    check_root_permissions,
    find_ports_from_state,
    validate_port_state_type,
    format_string)
from unittest.mock import MagicMock, patch


class TestUtils(unittest.TestCase):
    def test_n_hosts_on_subnet(self):
        r = n_hosts_on_subnet("10.0.0.0/24")
        self.assertEqual(r, 256)

        r = n_hosts_on_subnet("10.0.0.0/16")
        self.assertEqual(r, 65536)

        r = n_hosts_on_subnet("10.0.0.0/30")
        self.assertEqual(r, 4)

        r = n_hosts_on_subnet("10.0.0.0/28")
        self.assertEqual(r, 16)

    def test_hash_string(self):
        hashed = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        r = hash_string("test")
        self.assertEqual(r, hashed)

    def test_datetime_validation(self):
        r = datetime_validation("202401-01 00:00:00")
        self.assertEqual(r, False)

        r = datetime_validation("2024-01-01 00:00:00")
        self.assertEqual(r, True)

        r = datetime_validation("20240101 00:00:00")
        self.assertEqual(r, False)

    def test_datetime_normalization(self):
        r = datetime_normalization("202401-01")
        self.assertEqual(r, None)

        r = datetime_normalization("2024-01-01")
        self.assertEqual(r, "2024-01-01 00:00:00")

        r = datetime_normalization("20240101")
        self.assertEqual(r, None)

    def test_validate_host(self):
        r = validate_host("10.10.10.10")
        self.assertEqual(r, True)

        r = validate_host("fqdn.com")
        self.assertEqual(r, True)

        r = validate_host("invalid-host!_.com")
        self.assertEqual(r, False)

    @patch("deltascan.core.utils.os.getuid", MagicMock(return_value=1))
    def test_check_root_permissions(self):
        self.assertRaises(PermissionError, check_root_permissions)

    def test_find_ports_from_state(self):
        p = [
            {"portid": "80", "state": "open"},
            {"portid": "20", "state": "closed"},
            {"portid": "443", "state": "open"},
            {"portid": "9090", "state": "filtered"}]
        ropen = find_ports_from_state(p, "open")
        rclosed = find_ports_from_state(p, "closed")
        rfiltered = find_ports_from_state(p, "filtered")

        self.assertEqual(ropen, [{"portid": "80", "state": "open"},
                                 {"portid": "443", "state": "open"}])
        self.assertEqual(rclosed, [{"portid": "20", "state": "closed"}])
        self.assertEqual(rfiltered, [{"portid": "9090", "state": "filtered"}])

    def test_validate_port_state_type(self):
        r = validate_port_state_type(["open"])
        self.assertEqual(r, True)

        r = validate_port_state_type(["filtered"])
        self.assertEqual(r, True)

        r = validate_port_state_type(["wronf"])
        self.assertEqual(r, False)

    def test_format_string(self):
        new_string = format_string("This is a test string")
        self.assertEqual(new_string, "This is a test string")

        new_string = format_string("field_1")
        self.assertEqual(new_string, "Field 1")

        new_string = format_string("field 1")
        self.assertEqual(new_string, "Field 1")
