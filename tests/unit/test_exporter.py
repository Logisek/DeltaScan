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
from .test_data.mock_data import (
    DIFFS, SCANS_FROM_DB_TEST_V1, REPORT_DIFFS)
from deltascan.core.exceptions import (ExporterExceptions)
from deltascan.core.export import Exporter


class TestExporter(unittest.TestCase):
    def test_invalid_filename(self):
        with self.assertRaises(ExporterExceptions.DScanExporterFileExtensionNotSpecified):
            _ = Exporter(DIFFS, "test_file.xmll")

    def test_invalid_data(self):
        with self.assertRaises(ExporterExceptions.DScanExporterSchemaException):
            _ = Exporter({"diffs": DIFFS}, "valid_file.csv")

        with self.assertRaises(ExporterExceptions.DScanExporterSchemaException):
            _ = Exporter(
                {
                    "scans_from_db": SCANS_FROM_DB_TEST_V1
                }, "valid_file.csv")

    def test_diffs_to_csv(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._diffs_to_csv", MagicMock()) as mock_method_diffs_to_csv:
            self.exporter = Exporter(REPORT_DIFFS, f"{self.file}.csv", self.logger)
            self.exporter.export()
            mock_method_diffs_to_csv.assert_called_once()

    def test_single_diffs_to_csv(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._single_diffs_to_csv", MagicMock()) as mock_method_single_diffs_to_csv:
            self.exporter = Exporter(REPORT_DIFFS, f"{self.file}.csv", self.logger, single=True)
            self.exporter.export()
            mock_method_single_diffs_to_csv.assert_called_once()

    def test_scans_to_csv(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._scans_to_csv", MagicMock()) as mock_method_scans_to_csv:
            self.exporter = Exporter(SCANS_FROM_DB_TEST_V1, f"{self.file}.csv", self.logger)
            self.exporter.export()
            mock_method_scans_to_csv.assert_called_once()

    def test_single_scans_to_csv(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._single_scans_to_csv", MagicMock()) as mock_method_single_scans_to_csv:
            self.exporter = Exporter(SCANS_FROM_DB_TEST_V1, f"{self.file}.csv", self.logger, single=True)
            self.exporter.export()
            mock_method_single_scans_to_csv.assert_called_once()

    def test_diffs_to_html(self):
        self.file = "test.html"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._diffs_to_html", MagicMock()) as mock_method_diffs_to_html:
            self.exporter = Exporter(REPORT_DIFFS, f"{self.file}.html", self.logger)
            self.exporter.export()
            mock_method_diffs_to_html.assert_called_once()

    def test_diffs_to_pdf(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._diffs_to_pdf", MagicMock()) as mock_method_diffs_to_pdf:
            self.exporter = Exporter(REPORT_DIFFS, f"{self.file}.pdf", self.logger, single=True)
            self.exporter.export()
            mock_method_diffs_to_pdf.assert_called_once()

    def test_scans_to_html(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._scans_to_html", MagicMock()) as mock_method_scans_to_html:
            self.exporter = Exporter(SCANS_FROM_DB_TEST_V1, f"{self.file}.html", self.logger)
            self.exporter.export()
            mock_method_scans_to_html.assert_called_once()

    def test_scans_to_pdf(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        with patch("deltascan.core.export.Exporter._scans_to_pdf", MagicMock()) as mock_method_scans_to_pdf:
            self.exporter = Exporter(SCANS_FROM_DB_TEST_V1, f"{self.file}.pdf", self.logger, single=True)
            self.exporter.export()
            mock_method_scans_to_pdf.assert_called_once()
