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
from deltascan.core.parser import Parser
from .test_data.mock_data import (DIFFS, ARTICULATED_DIFFS)


class TestParser(unittest.TestCase):
    def test_dict_diff_to_list_diff(self):
        result = Parser._dict_diff_to_list_diff(DIFFS[0]["diffs"], [], "added")
        self.assertEqual(result, ARTICULATED_DIFFS[0]["added"])

        result = Parser._dict_diff_to_list_diff(DIFFS[0]["diffs"], [], "changed")
        self.assertEqual(result, ARTICULATED_DIFFS[0]["changed"])

        result = Parser._dict_diff_to_list_diff(DIFFS[0]["diffs"], [], "removed")
        self.assertEqual(result, ARTICULATED_DIFFS[0]["removed"])

        result = Parser._dict_diff_to_list_diff(DIFFS[1]["diffs"], [], "added")
        self.assertEqual(result, ARTICULATED_DIFFS[1]["added"])

        result = Parser._dict_diff_to_list_diff(DIFFS[1]["diffs"], [], "changed")
        self.assertEqual(result, ARTICULATED_DIFFS[1]["changed"])

        result = Parser._dict_diff_to_list_diff(DIFFS[1]["diffs"], [], "removed")
        self.assertEqual(result, ARTICULATED_DIFFS[1]["removed"])

    def test_diffs_to_output_format(self):
        results = Parser.diffs_to_output_format(DIFFS[0])
        self.assertEqual(results, ARTICULATED_DIFFS[0])

        results = Parser.diffs_to_output_format(DIFFS[1])
        self.assertEqual(results, ARTICULATED_DIFFS[1])
