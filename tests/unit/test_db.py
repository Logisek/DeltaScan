from unittest import TestCase
from unittest.mock import MagicMock, patch
import os
from deltascan.core.db.manager import RDBMS

class TestSQLiteDatabase(TestCase):
    def setUp(self):
        self.manager = RDBMS()

    def test_create_profile(self):
        self.manager.create_profile("TEST_1", "test_args")

    def test_create_database(self):
        self.manager.create_profile("TEST_1", "test_args")
        result_id = self.manager.create_port_scan(
            "0.0.0.0", "unknown", "TEST_1", '{"data": "test_data"}', "hash", None
        )
        self.assertEqual(1,result_id)