import unittest
from unittest.mock import MagicMock, patch
from deltascan.core.importer import Importer

class TestImporter(unittest.TestCase):
    def setUp(self):
        self.file = "test.csv"
        self.logger = MagicMock()
        self.importer = Importer(self.file, self.logger)

    def test_compare_nmap_arguments(self):
        self.assertEqual(True,
            self.importer._compare_nmap_arguments(
                ["-sV", "-p1-100"],
                ["-sV", "-p1-100"]))
        self.assertEqual(True,
            self.importer._compare_nmap_arguments(
                ["--osscan", "--version-all", "-sS"],
                ["-sS","--version-all", "--osscan"]))
        self.assertEqual(False,
            self.importer._compare_nmap_arguments(
                ["--osscan", "--version-all", "-sS"],
                ["-sV", "--osscan"]))