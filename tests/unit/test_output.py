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
from deltascan.core.output import Output
from .test_data.mock_data import (REPORT_DIFFS)


class TestOutput(unittest.TestCase):
    def setUp(self):
        self.output = Output()

    def test_construct_exported_diff_data(self):
        result = self.output._construct_exported_diff_data(
            REPORT_DIFFS[0],
            ["change", "field_1", "field_2", "from", "to"])
        self.assertEqual(
            result, [{
                'change': 'changed',
                'field_1': 'osfingerprint',
                'field_2': '',
                'from': 'os_fingerprint_old',
                'to': 'os_fingerprint_new'
            }])

        result = self.output._construct_exported_diff_data(
            REPORT_DIFFS[1],
            ["change", "field_1", "field_2", "field_3", "field_4", "from", "to"])
        self.assertEqual(
            result, [
                {
                    'change': 'changed',
                    'field_1': 'ports',
                    'field_2': '120',
                    'field_3': 'state',
                    'field_4': '',
                    'from': 'open',
                    'to': 'closed'
                },
                {
                    'change': 'added',
                    'field_1': 'new_data',
                    'field_2': 'of',
                    'field_3': 'any',
                    'field_4': 'type',
                    'from': '',
                    'to': ''
                },
                {
                    'change': 'removed',
                    'field_1': 'status',
                    'field_2': 'good',
                    'field_3': '',
                    'field_4': '',
                    'from': '',
                    'to': ''
                }
            ]
        )
