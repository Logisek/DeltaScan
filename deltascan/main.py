import deltascan.core.scanner as scanner
import deltascan.core.store as store
import deltascan.cli.data_presentation as data_presentation
import deltascan.core.reports.pdf as pdf
from deltascan.core.config import CONFIG_FILE_PATH, DEFAULT_PROFILE
from deltascan.core.exceptions import (DScanInputValidationException,
                                       DScanRDBMSException,
                                       DScanException,
                                       DScanRDBMSEntryNotFound)
import logging
import os
import re
import yaml

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing results, and generating reports.
    """

    def __init__(self):
        self.store = store.Store()
        self.scanner = scanner.Scanner()

    def _checkRootPermissions(self):
        """
        Checks if the program is running with root permissions.
        """
        try:
            if os.getuid() != 0:
                raise PermissionError("You need root permissions to run this program.")
        except PermissionError as e:
            logger.error(e)
            print("You need root permissions to run this program.")
            exit()
        except Exception as e:
            logger.error(f"{str(e)}")

    def _validate_host(self, value):
        """
        Validates the given host value.

        Args:
            value (str): The host value to be validated.

        Returns:
            bool or str: Returns True if the host is valid. Otherwise, returns an error message.

        Raises:
            DScanInputValidationException: If an exception occurs during the validation process.
        """
        if not re.match(r"^[a-zA-Z0-9.-/]+$", value):
            return False
        return True

    def _validate_arguments(self, value):
        """
        Validates the given argument value.

        Args:
            value (str): The argument value to be validated.

        Returns:
            bool or str: Returns True if the argument value is valid. Otherwise, returns an error message.

        Raises:
            DScanInputValidationException: If an exception occurs during the validation process.

        """
        if not re.match(r"^[a-zA-Z0-9\s-]+$", value):
            return False
        return True
    
    def _load_profiles_from_file(self, path=None):
        """
        Load profiles from a YAML file and save them to the store.

        This method reads the profiles data from a YAML file specified by `CONFIG_FILE_PATH`,
        and saves the profiles to the store using the `save_profiles` method of the `store` object.

        Returns:
            None

        Raises:
            FileNotFoundError: If the YAML file specified by `CONFIG_FILE_PATH` does not exist.
            yaml.YAMLError: If there is an error while parsing the YAML file.
        """
        yaml_file_path = CONFIG_FILE_PATH if path is None else path

        with open(yaml_file_path, "r") as file:
            data = yaml.safe_load(file)

        return data["profiles"]

    def port_scan(self, profile_file, profile_name, host):
        """
        Perform a port scan on the specified host using the given arguments.

        Args:
            profile_file (str): The path to the profile file.
            profile (str): The profile to use for the scan.
            host (str): The target host to scan.

        Raises:
            ValueError: If the host or arguments are invalid.
            DScanInputValidationException: If there is an input validation error.
            Exception: If any other error occurs during the scan.

        Returns:
            None
        """
        try:
            profile = self._load_profiles_from_file(profile_file)[profile_name]
            self.store.save_profiles({profile_name: profile})
            profile_arguments = profile["arguments"]
        except (KeyError, IOError) as e:
            logger.warning(f"{str(e)}")
            print(f"Profile {profile_name} not found in file. "
                   "Searching for profile in database...")

        try:
            profile = self.store.get_profile(profile_name)
            profile_arguments = profile["arguments"]
        except DScanRDBMSEntryNotFound:
            logger.error(f"Profile {profile_name} not found in database")
            raise DScanRDBMSException("Profile not found in database. Please check your profile name.")
        self._checkRootPermissions()
        print(profile_arguments)
        try:
            if self._validate_host(host) is False:
                raise DScanInputValidationException("Invalid host format")
            print(host, profile_arguments)
            results = self.scanner.scan(host, profile_arguments)
            subnet = "" if len(host.split("/")) else host.split("/")[1]
            self.store.save_scans(profile_name, subnet, results, profile_arguments)

        except ValueError as e:
            logger.error(f"{str(e)}")
            raise DScanException("An error occurred during the scan. Please check your host and arguments.")
        print("\nDone :)")
        return 0

    def view(self):
        """
        Displays the scan list, profile list, and scan results.
        """
        try:
            scanList = self.dataHandler.getScanList()
            data_presentation.displayScanList(scanList)

            profileList = self.dataHandler.getProfileList()
            data_presentation.displayProfileList(profileList)

            results = self.dataHandler.getScanResults(1)
            data_presentation.displayScanResults(results)

        except Exception as e:
            logger.error(f"{str(e)}")

    def pdf_report(self):
            """
            Generates a PDF report based on the scan results.

            This method retrieves the scan results using the `getScanResults` method from the `dataHandler` object.
            It then generates a PDF report using the `generatePdfReport` function, passing in the retrieved results.

            Raises:
                Exception: If an error occurs during the generation of the PDF report.

            """
            try:
                results = self.dataHandler.getScanResults(1)
                pdf.generatePdfReport("default", results)
            except Exception as e:
                logger.error(f"{str(e)}")
