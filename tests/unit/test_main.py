from unittest import TestCase, skip
from unittest.mock import MagicMock, patch, call

from deltascan.core.exceptions import (DScanException,
                                       DScanRDBMSException,
                                       DScanInputValidationException,
                                       DScanResultsSchemaException)
from deltascan.core.export import Reporter
from deltascan.main import DeltaScan
from .test_data.mock_data import (mock_data_with_real_hash,
                       SCANS_FROM_DB_TEST_V1,
                       SCANS_FROM_DB_TEST_V1_PORTS_KEYS)

TEST_DATA = "tests/unit/test_data"
CONFIG_FILE = f"{TEST_DATA}/config.yaml"
INVALID_CONFIG_FILE = f"{TEST_DATA}/wrong-config.yaml"

class TestMain(TestCase):
    def setUp(self):
        config = {
            "output_file": None,
            "action": "view",
            "profile": "TEST_V1",
            "conf_file": CONFIG_FILE,
            "verbose": False,
            "n_scans": 1,
            "n_diffs": 1,
            "date": "2024-03-09 10:00:00",
            "port_type": "open",
            "host": "0.0.0.0"
        }
        self.dscan = DeltaScan(config)

    def mock_scanner(self):
        self.dscan.scanner = MagicMock()
        self.dscan.scanner.scan.return_value = MagicMock()
    
    def mock_store(self):
        self.dscan.store = MagicMock()
        self.dscan.store.save_profiles.return_value = MagicMock()
        self.dscan.store.get_profile.return_value = MagicMock()

    def test_port_scan_missing_profile_name(self):
        self.dscan.config.conf_file = CONFIG_FILE
        self.dscan.config.profile = "TEST_V1_NOT_EXIST"

        self.assertRaises(
            DScanRDBMSException,
            self.dscan.port_scan)

    def test_port_scan_missing_conf_file(self):
        self.dscan.config.conf_file = INVALID_CONFIG_FILE
        self.dscan.config.profile = "TEST_V1_NOT_EXIST"

        self.assertRaises(
            DScanException,
            self.dscan.port_scan)
    
    @patch("deltascan.main.check_root_permissions", MagicMock())
    def test_port_scan_save_profile_in_database(self):
        self.mock_store()
        self.mock_scanner()

        self.dscan.config.conf_file = CONFIG_FILE

        self.dscan.port_scan()

        self.dscan.store.save_profiles.assert_called_once_with(
            {"TEST_V1": {"arguments": "-sS -n -Pn --top-ports 1000 --reason"}}
        )

    @patch("deltascan.main.check_root_permissions", MagicMock())
    def test_port_scan_search_profile_in_database(self):
        self.mock_store()
        self.mock_scanner()

        self.dscan.config.conf_file = INVALID_CONFIG_FILE

        self.dscan.port_scan()

        self.dscan.store.get_profile.assert_called_once_with("TEST_V1")

    @patch("deltascan.main.check_root_permissions", MagicMock())
    def test_port_scan_save_scan_invalid_host(self):
        self.mock_store()
        self.mock_scanner()
        self.dscan.config.host = "@sa"

        self.assertRaises(
            DScanInputValidationException,
            self.dscan.port_scan)
    
    @patch("deltascan.main.check_root_permissions", MagicMock())
    def test_port_scan_and_save_success(self):
        self.mock_store()
        self.mock_scanner()

        self.dscan.config.conf_file = CONFIG_FILE
        self.dscan.port_scan()

        self.dscan.scanner.scan.assert_called_once_with(
            "0.0.0.0",
            self.dscan.store.get_profile.return_value["arguments"]
        )
        self.dscan.store.save_scans.assert_called_once_with(
            "TEST_V1", "",
            self.dscan.scanner.scan.return_value, 
            self.dscan.store.get_profile.return_value["arguments"]
        )

    def test_compare_date_validation_error(self):
        self.dscan.config.date = "2021-01-01"
        self.dscan.config.n_diffs = 4
        self.dscan.config.conf_file = "CUSTOM_PROFILE"
        self.assertRaises(
            DScanInputValidationException,
            self.dscan.compare)
    
    def test_compare_success(self):
        self.mock_store()
        last_n_scan_results = mock_data_with_real_hash(SCANS_FROM_DB_TEST_V1)
        self.dscan._list_scans_with_diffs = MagicMock()
        self.dscan.store.get_last_n_scans_for_host.return_value = last_n_scan_results
        self.dscan.config.date = "2021-01-01 12:00:00"
        self.dscan.config.n_scans = 4
        self.dscan.config.profile = "CUSTOM_PROFILE"

        self.dscan.compare()

        self.dscan.store.get_last_n_scans_for_host.assert_called_once_with(
            "0.0.0.0", 4, "CUSTOM_PROFILE", "2021-01-01 12:00:00", 
        )

        self.dscan._list_scans_with_diffs.assert_called_once_with(
           last_n_scan_results, 
        )

    def test_list_scans_with_diffs_success(self):
        self.mock_store()
        results_to_find_diffs = mock_data_with_real_hash(SCANS_FROM_DB_TEST_V1)
        _results_to_port_dict_results = SCANS_FROM_DB_TEST_V1_PORTS_KEYS

        self.dscan._results_to_port_dict = MagicMock(
            side_effect=[
                _results_to_port_dict_results[0]["results"],
                _results_to_port_dict_results[1]["results"],
                _results_to_port_dict_results[1]["results"],
                _results_to_port_dict_results[2]["results"]
            ])
        self.dscan._diffs_between_dicts = MagicMock()
        self.dscan._diffs_between_dicts = MagicMock(side_effect=[
            {"added": "1", "removed": "", "changed": ""},
            {"added": "", "removed": "2", "changed": ""},
        ])
        calls = [
            call( _results_to_port_dict_results[0]["results"],  _results_to_port_dict_results[1]["results"]),
            call( _results_to_port_dict_results[1]["results"],  _results_to_port_dict_results[2]["results"])]
        res = self.dscan._list_scans_with_diffs(results_to_find_diffs)

        self.dscan._diffs_between_dicts.assert_has_calls(calls)
        self.assertEqual(res, [
            {
                "ids": [1, 2],
                "dates": ["2021-01-01 00:00:00", "2021-01-02 00:00:00"],
                "diffs": {"added": "1", "removed": "", "changed": ""},
                "result_hashes": [results_to_find_diffs[0]["result_hash"], results_to_find_diffs[1]["result_hash"]]
            },
            {
                "ids": [2, 3],
                "dates": ["2021-01-02 00:00:00", "2021-01-03 00:00:00"],
                "diffs": {"added": "", "removed": "2", "changed": ""},
                "result_hashes": [results_to_find_diffs[1]["result_hash"], results_to_find_diffs[2]["result_hash"]]
            }])
        
    def test_results_to_port_dict_success(self):
        _results_to_port_dict_results = SCANS_FROM_DB_TEST_V1_PORTS_KEYS[0]
        _results_to_port_dict_results["result_hash"] = mock_data_with_real_hash(SCANS_FROM_DB_TEST_V1)[0]["result_hash"]
        self.assertEqual(
            self.dscan._results_to_port_dict(SCANS_FROM_DB_TEST_V1[0]),
            _results_to_port_dict_results["results"]
        )

    def test_results_to_port_dict_schema_error(self):
        self.assertRaises(
            DScanResultsSchemaException,
            self.dscan._results_to_port_dict,
           {"wrongly": "formatted", "data": "here"})
        
    def test_diffs_between_dicts_success(self):
        res = self.dscan._diffs_between_dicts(
            {"a": 1, "b": 2, "c": {"d": 1, "e": 2}},
            {"a": 1, "b": 3, "c": {"d": 1, "e": 3}}
        )
        self.assertEqual(res,
            {
                "added": {},
                "removed": {},
                "changed": {
                "b": {
                    "from": 3,
                    "to": 2
                },
                "c": {
                    "added": {},
                    "removed": {},
                    "changed": {
                        "e": {
                            "from": 3,
                            "to": 2
                        }
                    }
                }
            }})
        
        res = self.dscan._diffs_between_dicts(
            {"a": 1, "b": 2, "c": {"added": 1, "e": 2}},
            {"a": 1, "b": 3, "c": {"d": 1, "e": 3}}
        )
        self.assertEqual(res,
            {
                "added": {},
                "removed": {},
                "changed": {
                "b": {
                    "from": 3,
                    "to": 2
                },
                "c": {
                    "added": {"added": 1},
                    "removed": {"d": 1},
                    "changed": {
                        "e": {
                            "from": 3,
                            "to": 2
                        }
                    }
                }
            }})
    
    @patch('deltascan.main.Reporter', MagicMock())
    def test_view_date_validation_error(self):
        self.dscan.config.date = "20240309 10:00:00"

        self.assertRaises(
            DScanInputValidationException,
            self.dscan.view)
    
    @patch('deltascan.main.Reporter', MagicMock())
    def test_view_port_state_validation_error(self):
        self.dscan.config.profile = "CUSTOM_PROFILE"
        self.dscan.config.date = "2024-03-09 10:00:00"
        self.dscan.config.port_type = "wrong_port_state"

        self.assertRaises(
            DScanInputValidationException,
            self.dscan.view)
    
    @patch('deltascan.main.Reporter', MagicMock())
    def test_view_success(self):
        self.mock_store()
        self.dscan.store.get_filtered_scans = MagicMock()

        self.dscan.config.profile = "CUSTOM_PROFILE"
        self.dscan.config.date = "2024-03-09 10:00:00"
        self.dscan.config.n_scans = 4
        self.dscan.config.port_type = "open"
        self.dscan.view()
        
        self.dscan.store.get_filtered_scans.assert_called_once_with(
            host="0.0.0.0",
            last_n=4,
            profile="CUSTOM_PROFILE",
            creation_date="2024-03-09 10:00:00",
            pstate="open")