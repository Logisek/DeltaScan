from unittest import TestCase
from unittest.mock import MagicMock, patch
import os
from deltascan.core.db.manager import RDBMS

class TestSQLiteDatabase(TestCase):
    def setUp(self):
        self.manager = RDBMS()
    
    # WARNING: the tests run in order they appear here due to their name
    # Their names are ordered alphabetically: test_a_<name>, test_b_<name>, etc.
    def test_a_profile_create_and_get_database_success(self):
        result_id = self.manager.create_profile("TEST_1", "test_args")
        self.assertEqual(1, result_id)

        result_id = self.manager.create_profile("TEST_2", "test_args")
        self.assertEqual(2, result_id)

        r = list(self.manager.get_profiles())
        r[0]["created_at"] = None
        r[1]["created_at"] = None
        self.assertEqual(2, len(r))
        self.assertEqual(r, [
            {"id": 1,
             "profile_name": "TEST_1",
             "arguments": "test_args",
             "created_at": None},
            {"id": 2,
             "profile_name": "TEST_2",
             "arguments": "test_args",
             "created_at": None}
        ])
    
        r = self.manager.get_profile("TEST_1")
        r["created_at"] = None
        self.assertEqual(r, {"id": 1,
             "profile_name": "TEST_1",
             "arguments": "test_args",
             "created_at": None},
        )

    def test_b_port_scans_create_and_get_database_success(self):
        self.manager.create_profile("TEST_3", "test_args")
        result = self.manager.create_port_scan(
            "uuid_1", "0.0.0.0", "0.0.0.0/24", "unknown", "TEST_3", '{"data": "test_data"}', "hash", None
        )
        self.assertEqual(1,result.id)

        self.manager.create_profile("TEST_4", "test_args")
        result = self.manager.create_port_scan(
            "uuid_2", "0.0.0.0", "0.0.0.0/24","unknown", "TEST_4", '{"data": "test_data"}', "hash", None
        )
        self.assertEqual(2,result.id)

        r1 = list(self.manager.get_scans(None, "0.0.0.0", 1, "TEST_3"))
        self.assertEqual(1, len(r1))
        # a small hack to bypass the current datetime
        r1[0]["created_at"] = None
        self.assertEqual(r1, [
            {"id": 1,
             "uuid": "uuid_1",
             "host": "0.0.0.0",
             "host_subnet": "0.0.0.0/24",
             "profile_name": "TEST_3",
             "arguments": "test_args",
             "results": '{"data": "test_data"}',
             "result_hash": "hash",
             "created_at": None}
        ])

        r2 = list(self.manager.get_scans(None, "0.0.0.0", 2, None))
        self.assertEqual(2, len(r2))
        # a small hack to bypass the current datetime
        r2[0]["created_at"] = None
        r2[1]["created_at"] = None
        self.assertEqual(r2, [
            {"id": 1,
             "uuid": "uuid_1",
             "host": "0.0.0.0",
             "host_subnet": "0.0.0.0/24",
             "profile_name": "TEST_3",
             "arguments": "test_args",
             "results": '{"data": "test_data"}',
             "result_hash": "hash",
             "created_at": None},
            {"id": 2,
             "uuid": "uuid_2",
             "host": "0.0.0.0",
             "host_subnet": "0.0.0.0/24",
             "profile_name": "TEST_4",
             "arguments": "test_args",
             "results": '{"data": "test_data"}',
             "result_hash": "hash",
             "created_at": None}
        ])

        r2 = list(self.manager.get_scans(None, "0.0.0.0", 2, "TEST_3"))
        self.assertEqual(1, len(r2))
        # a small hack to bypass the current datetime
        r2[0]["created_at"] = None
        self.assertEqual(r2, [
            {"id": 1,
             "uuid": "uuid_1",
             "host": "0.0.0.0",
             "host_subnet": "0.0.0.0/24",
             "profile_name": "TEST_3",
             "arguments": "test_args",
             "results": '{"data": "test_data"}',
             "result_hash": "hash",
             "created_at": None},
        ])
