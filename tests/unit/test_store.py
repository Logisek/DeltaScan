import unittest
import json
import copy
from unittest.mock import MagicMock, patch
from .test_data.mock_data import (
    SCANS_FROM_DB_JSON_STRING_TEST_V1, SCANS_FROM_DB_TEST_V1)
from deltascan.core.exceptions import DScanResultsSchemaException
from deltascan.core.store import Store


class TestStore(unittest.TestCase):
    @patch("deltascan.core.store.RDBMS", MagicMock(create_port_scan=MagicMock()))
    def setUp(self):
        self.store = Store()

    @patch("deltascan.core.store.uuid", MagicMock(uuid4=MagicMock(return_value="uuid")))
    @patch("deltascan.core.store.hash_string", MagicMock(return_value="hash_string"))
    def test_save_scans(self):
        self.store.save_scans(
            "profile_name",
            "host_with_subnet",
            [SCANS_FROM_DB_TEST_V1[0]["results"]])

        self.store.rdbms.create_port_scan.assert_called_once_with(
            "uuid",
            "0.0.0.0",
            "host_with_subnet",
            "unknown",
            "profile_name",
            json.dumps(SCANS_FROM_DB_TEST_V1[0]["results"]),
            "hash_string",
            None,
            created_at=None
        )

    @patch("deltascan.core.store.uuid", MagicMock(uuid4=MagicMock(return_value="uuid")))
    @patch("deltascan.core.store.hash_string", MagicMock(return_value="hash_string"))
    def test_save_scans_error(self):
        with self.assertRaises(DScanResultsSchemaException):
            self.store.save_scans(
                "profile_name",
                "host_with_subnet",
                [{"invalid": SCANS_FROM_DB_TEST_V1[0]["results"]}])

    def test_save_profile(self):
        self.store.save_profiles({"profile_name": {"arguments": "arguments"}})
        self.store.rdbms.create_profile.assert_called_once_with(
            "profile_name",
            "arguments"
        )

    def test_get_filtered_scans(self):
        self.store.get_filtered_scans("uuid", "host", 1, "profile_name", pstate="open")
        self.store.rdbms.get_scans.assert_called_once_with("uuid", "host", 1, "profile_name", None, None)

    def test_get_scans_count(self):
        self.store.get_scans_count()
        self.store.rdbms.get_scans_count.assert_called_once_with()

    def test_get_profiles_count(self):
        self.store.get_profiles_count()
        self.store.rdbms.get_profiles_count.assert_called_once_with()

    def test_get_profile(self):
        self.store.get_profile("profile_name")
        self.store.rdbms.get_profile.assert_called_once_with("profile_name")

    def test_filter_results_and_transform_results_to_dict(self):
        _r = self.store._filter_results_and_transform_results_to_dict(
            copy.deepcopy(SCANS_FROM_DB_JSON_STRING_TEST_V1[0]), "all")
        self.assertEqual(len(_r["results"]["ports"]), 3)

        _r = self.store._filter_results_and_transform_results_to_dict(
            copy.deepcopy(SCANS_FROM_DB_JSON_STRING_TEST_V1[0]), "open")
        self.assertEqual(len(_r["results"]["ports"]), 2)

        _r = self.store._filter_results_and_transform_results_to_dict(
            copy.deepcopy(SCANS_FROM_DB_JSON_STRING_TEST_V1[0]), "closed")
        self.assertEqual(len(_r["results"]["ports"]), 1)
