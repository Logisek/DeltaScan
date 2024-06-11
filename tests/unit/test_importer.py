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

from unittest import TestCase
from unittest.mock import MagicMock
from deltascan.core.importer import Importer
from deltascan.core.store import Store


class TestImporter(TestCase):
    def setUp(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        store = Store("", self.logger)
        self.importer = Importer(
            store,
            self.file,
            self.logger)

    def test_compare_nmap_arguments(self):
        self.assertEqual(
            True,
            self.importer._compare_nmap_arguments(
                ["-sV", "-p1-100"],
                ["-sV", "-p1-100"]
            )
        )
        self.assertEqual(
            True,
            self.importer._compare_nmap_arguments(
                ["--osscan", "--version-all", "-sS"],
                ["-sS", "--version-all", "--osscan"]
            )
        )
        self.assertEqual(
            False,
            self.importer._compare_nmap_arguments(
                ["--osscan", "--version-all", "-sS"],
                ["-sV", "--osscan"]
            )
        )
