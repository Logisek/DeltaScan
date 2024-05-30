import unittest
from unittest.mock import MagicMock, patch
from .test_data.mock_data import (
    DIFFS, SCANS_FROM_DB_TEST_V1, REPORT_DIFFS)
from deltascan.core.exceptions import (DScanExporterSchemaException,
                                       DScanExporterFileExtensionNotSpecified)
from deltascan.core.export import Exporter

class TestExporter(unittest.TestCase):
    def test_invalid_filename(self):
        with self.assertRaises(DScanExporterFileExtensionNotSpecified):
            _ = Exporter(DIFFS, "test_file.xmll")

    def test_invalid_data(self):
        with self.assertRaises(DScanExporterSchemaException):
            _ = Exporter({"diffs": DIFFS}, "valid_file.csv")

        with self.assertRaises(DScanExporterSchemaException):
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
        with patch("deltascan.core.export.Exporter._single_diffs_to_csv", MagicMock()) \
            as mock_method_single_diffs_to_csv:
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
        with patch("deltascan.core.export.Exporter._single_scans_to_csv", MagicMock()) \
            as mock_method_single_scans_to_csv:
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
        with patch("deltascan.core.export.Exporter._diffs_to_pdf", MagicMock()) \
            as mock_method_diffs_to_pdf:
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
        with patch("deltascan.core.export.Exporter._scans_to_pdf", MagicMock()) \
            as mock_method_scans_to_pdf:
            self.exporter = Exporter(SCANS_FROM_DB_TEST_V1, f"{self.file}.pdf", self.logger, single=True)
            self.exporter.export()
            mock_method_scans_to_pdf.assert_called_once()
