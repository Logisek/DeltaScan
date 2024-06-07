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
