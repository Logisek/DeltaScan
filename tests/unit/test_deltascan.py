from unittest import TestCase
from unittest.mock import MagicMock, patch, call

from deltascan.core.exceptions import (AppExceptions)
from deltascan.core.deltascan import DeltaScan
from .test_data.mock_data import (
    mock_data_with_real_hash,
    SCANS_FROM_DB_TEST_V1,
    SCANS_FROM_DB_TEST_V1_PORTS_KEYS)

TEST_DATA = "tests/unit/test_data"
CONFIG_FILE = f"{TEST_DATA}/config.yaml"
INVALID_CONFIG_FILE = f"{TEST_DATA}/wrong-config.yaml"


class TestMain(TestCase):
    def setUp(self):
        config = {
            "is_interactive": False,
            "output_file": None,
            "single": False,
            "template_file": None,
            "import_file": None,
            "diff_files": None,
            "action": "view",
            "profile": "TEST_V1",
            "conf_file": CONFIG_FILE,
            "verbose": False,
            "suppress": False,
            "n_scans": 1,
            "n_diffs": 1,
            "fdate": "2024-03-09 10:00:00",
            "tdate": "2024-03-10 10:00:00",
            "port_type": "open",
            "host": "0.0.0.0"
        }
        self.dscan = DeltaScan(config)

    def mock_store(self):
        self.dscan.store = MagicMock()
        self.dscan.store.save_profiles.return_value = MagicMock()
        self.dscan.store.get_profile.return_value = MagicMock()

    @patch("deltascan.core.deltascan.check_root_permissions", MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_port_scan_save_profile_in_database(self):
        self.mock_store()

        self.dscan._config.conf_file = CONFIG_FILE

        self.dscan._port_scan()

        self.dscan.store.save_profiles.assert_called_once_with(
            {"TEST_V1": {"arguments": "-sS -n -Pn --top-ports 1000 --reason"}}
        )

    @patch("deltascan.core.deltascan.check_root_permissions", MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_port_scan_search_profile_in_database(self):
        self.mock_store()

        self.dscan._config.conf_file = INVALID_CONFIG_FILE

        self.dscan._port_scan()

        self.dscan.store.get_profile.assert_called_once_with("TEST_V1")

    @patch("deltascan.core.deltascan.check_root_permissions", MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_port_scan_save_scan_invalid_host(self):
        self.mock_store()
        self.dscan._config.host = "@sa"

        self.assertRaises(
            AppExceptions.DScanInputValidationException,
            self.dscan._port_scan)

    @patch("deltascan.core.deltascan.check_root_permissions", MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_port_scan_and_save_success(self):  # TODO: write more logic here
        self.mock_store()

        self.dscan._config.conf_file = CONFIG_FILE
        self.dscan._port_scan()

        self.dscan.store.save_scans.assert_called_once()

    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_diffs_date_validation_error(self):
        self.dscan._config.fdate = "2021-01-01"
        self.dscan._config.n_diffs = 4
        self.dscan._config.conf_file = "CUSTOM_PROFILE"
        self.assertRaises(
            AppExceptions.DScanInputValidationException,
            self.dscan.diffs)

    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_diffs_success(self):
        self.mock_store()
        last_n_scan_results = mock_data_with_real_hash(SCANS_FROM_DB_TEST_V1)
        self.dscan._list_scans_with_diffs = MagicMock()
        self.dscan.store.get_filtered_scans.return_value = last_n_scan_results
        self.dscan._config.fdate = "2021-01-01 12:00:00"
        self.dscan._config.tdate = "2021-01-21 12:00:00"
        self.dscan._config.n_scans = 4
        self.dscan._config.profile = "CUSTOM_PROFILE"

        self.dscan.diffs()

        self.dscan.store.get_filtered_scans.assert_called_once_with(
            uuid=None, host="0.0.0.0", last_n=4, profile="CUSTOM_PROFILE", from_date="2021-01-01 12:00:00", to_date="2021-01-21 12:00:00"
        )

        self.dscan._list_scans_with_diffs.assert_called_once_with(
           last_n_scan_results,
        )

    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_list_scans_with_diffs_success(self):
        self.mock_store()
        results_to_find_diffs = mock_data_with_real_hash(SCANS_FROM_DB_TEST_V1)
        _results_to_port_dict_results = SCANS_FROM_DB_TEST_V1_PORTS_KEYS
        self.dscan._config.n_diffs = 4

        self.dscan._results_to_port_dict = MagicMock(
            side_effect=[
                _results_to_port_dict_results[0],
                _results_to_port_dict_results[1],
                _results_to_port_dict_results[1],
                _results_to_port_dict_results[2]
            ])
        self.dscan._diffs_between_dicts = MagicMock()
        self.dscan._diffs_between_dicts = MagicMock(side_effect=[
            {"added": "1", "removed": "", "changed": ""},
            {"added": "", "removed": "2", "changed": ""},
        ])

        calls = [
            call(_results_to_port_dict_results[0],  _results_to_port_dict_results[1]),
            call(_results_to_port_dict_results[1],  _results_to_port_dict_results[2])]
        res = self.dscan._list_scans_with_diffs(results_to_find_diffs)
        self.dscan._diffs_between_dicts.assert_has_calls(calls)
        self.assertEqual(res, [
            {
                "ids": [1, 2],
                "uuids": ["uuid_1", "uuid_2"],
                "dates": ["2021-01-01 00:00:00", "2021-01-02 00:00:00"],
                "generic": [{
                    "host": "0.0.0.0",
                    "arguments": "-vv",
                    "profile_name": "TEST_V1"
                }, {
                    "host": "0.0.0.0",
                    "arguments": "-vv",
                    "profile_name": "TEST_V1"
                }],
                "diffs": {"added": "1", "removed": "", "changed": ""},
                "result_hashes": [results_to_find_diffs[0]["result_hash"], results_to_find_diffs[1]["result_hash"]]
            },
            {
                "ids": [2, 3],
                "uuids": ["uuid_2", "uuid_3"],
                "dates": ["2021-01-02 00:00:00", "2021-01-03 00:00:00"],
                "generic": [{
                    "host": "0.0.0.0",
                    "arguments": "-vv",
                    "profile_name": "TEST_V1"
                }, {
                    "host": "0.0.0.0",
                    "arguments": "-vv",
                    "profile_name": "TEST_V1"
                }],
                "diffs": {"added": "", "removed": "2", "changed": ""},
                "result_hashes": [results_to_find_diffs[1]["result_hash"], results_to_find_diffs[2]["result_hash"]]
            }])

    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_results_to_port_dict_success(self):
        _results_to_port_dict_results = SCANS_FROM_DB_TEST_V1_PORTS_KEYS[0]
        _results_to_port_dict_results["result_hash"] = mock_data_with_real_hash(SCANS_FROM_DB_TEST_V1)[0]["result_hash"]
        self.assertEqual(
            self.dscan._results_to_port_dict(SCANS_FROM_DB_TEST_V1[0]["results"]),
            _results_to_port_dict_results["results"]
        )

    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_results_to_port_dict_schema_error(self):
        self.assertRaises(
            AppExceptions.DScanResultsSchemaException,
            self.dscan._results_to_port_dict,
            {"wrongly": "formatted", "data": "here"})

    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_diffs_between_dicts_success(self):
        res = self.dscan._diffs_between_dicts(
            {"a": 1, "b": 2, "c": {"d": 1, "e": 2}},
            {"a": 1, "b": 3, "c": {"d": 1, "e": 3}}
        )
        self.assertEqual(res, {
                "added": {},
                "removed": {},
                "changed": {
                    "b": {
                        "from": 3,
                        "to": 2
                    },
                    "c": {
                        "e": {
                            "from": 3,
                            "to": 2
                        }
                    }
                }
            }
        )

        res = self.dscan._diffs_between_dicts(
            {"a": 1, "b": 2, "c": {"added": 1, "e": 2}},
            {"a": 1, "b": 3, "c": {"d": 1, "e": 3}}
        )
        self.assertEqual(res, {
                "added": {"c": {"added": "-"}},
                "removed": {"c": {"d": "_"}},
                "changed": {
                    "b": {
                        "from": 3,
                        "to": 2
                    },
                    "c": {
                        "e": {
                            "from": 3,
                            "to": 2
                        }
                    }
                }
            }
        )

    @patch('deltascan.core.deltascan.Exporter', MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_view_date_validation_error(self):
        self.dscan._config.fdate = "20240309 10:00:00"

        self.assertRaises(
            AppExceptions.DScanInputValidationException,
            self.dscan.view)

    @patch('deltascan.core.deltascan.Exporter', MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_view_port_state_validation_error(self):
        self.dscan._config.profile = "CUSTOM_PROFILE"
        self.dscan._config.date = "2024-03-09 10:00:00"
        self.dscan._config.port_type = "wrong_port_state"

        self.assertRaises(
            AppExceptions.DScanInputValidationException,
            self.dscan.view)

    @patch('deltascan.core.deltascan.Exporter', MagicMock())
    @patch("deltascan.core.deltascan.Scanner", MagicMock())
    def test_view_success(self):
        self.mock_store()
        self.dscan.store.get_filtered_scans = MagicMock()

        self.dscan._config.profile = "CUSTOM_PROFILE"
        self.dscan._config.fdate = "2024-03-09 10:00:00"
        self.dscan._config.tdate = "2024-03-10 10:00:00"
        self.dscan._config.n_scans = 4
        self.dscan._config.port_type = "open"
        self.dscan.view()

        self.dscan.store.get_filtered_scans.assert_called_once_with(
            host="0.0.0.0",
            last_n=4,
            profile="CUSTOM_PROFILE",
            from_date="2024-03-09 10:00:00",
            to_date="2024-03-10 10:00:00",
            pstate="open")
