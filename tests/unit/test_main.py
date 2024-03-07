from unittest import TestCase
from unittest.mock import MagicMock, patch
from deltascan.main import DeltaScan
from deltascan.core.exceptions import (DScanException,
                                       DScanRDBMSException,
                                       DScanInputValidationException)

TEST_DATA = "tests/unit/test_data"
CONFIG_FILE = f"{TEST_DATA}/config.yaml"
INVALID_CONFIG_FILE = f"{TEST_DATA}/wrong-config.yaml"

class TestMain(TestCase):
    @patch('deltascan.core.config.DATABASE', f"{TEST_DATA}/test_db.sql")
    def setUp(self):
        self.dscan = DeltaScan()

    def mock_scanner(self):
        self.dscan.scanner = MagicMock()
        self.dscan.scanner.scan.return_value = MagicMock()
    
    def mock_store(self):
        self.dscan.store = MagicMock()
        self.dscan.store.save_profiles.return_value = MagicMock()
        self.dscan.store.get_profile.return_value = MagicMock()

    def test_port_scan_missing_profile_name(self):
        self.assertRaises(
            DScanRDBMSException,
            self.dscan.port_scan,
            CONFIG_FILE, "TEST_V1_NOT_EXIST", "0.0.0.0")

    def test_port_scan_missing_conf_file(self):
        self.assertRaises(
            DScanException,
            self.dscan.port_scan,
            INVALID_CONFIG_FILE, "TEST_V1_NOT_EXIST", "0.0.0.0")
    
    def test_port_scan_save_profile_in_database(self):
        self.mock_store()
        self.mock_scanner()
        self.dscan._checkRootPermissions = MagicMock()

        self.dscan.port_scan(CONFIG_FILE, "TEST_V1", "0.0.0.0")

        self.dscan.store.save_profiles.assert_called_once_with(
            {"TEST_V1": {"arguments": "-sS -n -Pn --top-ports 1000 --reason"}}
        )

    def test_port_scan_search_profile_in_database(self):
        self.mock_store()
        self.mock_scanner()
        self.dscan._checkRootPermissions = MagicMock()

        self.dscan.port_scan(INVALID_CONFIG_FILE, "TEST_V1", "0.0.0.0")

        self.dscan.store.get_profile.assert_called_once_with("TEST_V1")

    def test_port_scan_save_scan_invalid_host(self):
        self.mock_store()
        self.mock_scanner()
        self.dscan._checkRootPermissions = MagicMock()

        self.assertRaises(
            DScanInputValidationException,
            self.dscan.port_scan,
            CONFIG_FILE, "TEST_V1", "@sa")
        
    def test_port_scan_and_save_success(self):
        self.mock_store()
        self.mock_scanner()
        self.dscan._checkRootPermissions = MagicMock()

        self.dscan.port_scan(CONFIG_FILE, "TEST_V1", "0.0.0.0")

        self.dscan.scanner.scan.assert_called_once_with(
            "0.0.0.0",
            self.dscan.store.get_profile.return_value["argument"]
        )
        self.dscan.store.save_scans.assert_called_once_with(
            "TEST_V1", "",
            self.dscan.scanner.scan.return_value, 
            self.dscan.store.get_profile.return_value["argument"]
        )
        