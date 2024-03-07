from unittest import TestCase
from unittest.mock import MagicMock, patch
import os

TEST_DATA = "tests/unit/test_data"
DATABASE_PATH = f"{TEST_DATA}/test_db.db"

class TestSQLiteDatabase(TestCase):
    @patch("deltascan.core.config.DATABASE", DATABASE_PATH)
    def setUp(self):
        # os.remove(DATABASE_PATH)
        from deltascan.core.db.manager import RDBMS

        self.manager = RDBMS()

    def test_create_profile(self):
        self.manager.create_profile("TEST_1", "test_args")

    def test_create_database(self):
        self.manager.create_profile("TEST_1", "test_args")
        result_id = self.manager.create_port_scan(
            "0.0.0.0", "unknown", "TEST_1", '{"data": "test_data"}', "hash", None
        )
        self.assertEqual(1,result_id)