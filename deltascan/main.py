import deltascan.core.scanner as scanner
import deltascan.core.store as store
import deltascan.cli.data_presentation as data_presentation
import deltascan.core.reports.pdf as pdf
from deltascan.core.config import CONFIG_FILE_PATH, DEFAULT_PROFILE
from deltascan.core.exceptions import (DScanInputValidationException,
                                       DScanRDBMSException,
                                       DScanException,
                                       DScanRDBMSEntryNotFound)
from deltascan.core.utils import (datetime_validation,
                                  validate_host,
                                  check_root_permissions,
                                  n_hosts_on_subnet)
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
            if "/" in host:
                print("Scanning ",
                      n_hosts_on_subnet(host),
                      "hosts . Network: ", host)

            profile = self.store.get_profile(profile_name)
            profile_arguments = profile["arguments"]
        except DScanRDBMSEntryNotFound:
            logger.error(f"Profile {profile_name} not found in database")
            raise DScanRDBMSException("Profile not found in database. Please check your profile name.")
        
        try:
            check_root_permissions()
        except PermissionError as e:
            logger.error(e)
            print("You need root permissions to run this program.")
            os._exit(1)
        try:
            if validate_host(host) is False:
                raise DScanInputValidationException("Invalid host format")

            results = self.scanner.scan(host, profile_arguments)
            self.store.save_scans(
                profile_name,
                "" if len(host.split("/")) else host.split("/")[1], # Subnet
                results,
                profile_arguments
            )

        except ValueError as e:
            logger.error(f"{str(e)}")
            raise DScanException("An error occurred during the scan. Please check your host and arguments.")

        return results
    
    def compare(self, host, n_scans, date, profile):
        """
        Compares the last n scans for a given host.

        Args:
            n_scans (int): The number of scans to compare.
            date (str): The date to compare the scans from.

        Returns:
            None
        """
        try:
            if datetime_validation(date) is False:
                raise DScanInputValidationException("Invalid date format")

            scans = self.store.get_last_n_scans_for_host(
                    host, n_scans, profile, date
                )
            categorized_deltas = self._categorize_deltas(scans)
        except DScanRDBMSEntryNotFound as e:
            logger.error(f"{str(e)}")
            print(f"No scan results found for host {host}")

    def _categorize_deltas(self, scans):
        """
        Categorizes the deltas based on profile name and result hash.

        Args:
            scans (list): A list of scan objects.

        Returns:
            dict: A dictionary containing the categorized deltas.
                The keys of the dictionary are the profile names.
                The values of the dictionary are dictionaries where the keys are the result hashes
                and the values are lists of scan IDs.
        """
        similar_scan_ids = {}
        hash_order = []
        for i in range(len(scans)):
            if str(scans[i]["profile_name"]) not in similar_scan_ids:
                similar_scan_ids[str(scans[i]["profile_name"])] = {}
                
            if scans[i]["result_hash"] not in similar_scan_ids[str(scans[i]["profile_name"])]:
                similar_scan_ids[str(scans[i]["profile_name"])][scans[i]["result_hash"]] = []
                hash_order.append(scans[i]["result_hash"])

            similar_scan_ids[str(scans[i]["profile_name"])][scans[i]["result_hash"]].append(scans[i]["id"])
        return similar_scan_ids
        

    def view(self, host, n_scans, date, profile):
        """
        Displays the scan list, profile list, and scan results.
        """
        try:
            if date is not None and datetime_validation(date) is False:
                raise DScanInputValidationException("Invalid date format")
            return self.store.get_filtered_scans(
                    host=host, last_n=n_scans, profile=profile, creation_date=date
                )
        except DScanRDBMSEntryNotFound as e:
            logger.error(f"{str(e)}")
            print(f"No scan results found for host {host}")

    # def pdf_report(self):
    #     """
    #     Generates a PDF report based on the scan results.

    #     This method retrieves the scan results using the `getScanResults` method from the `dataHandler` object.
    #     It then generates a PDF report using the `generatePdfReport` function, passing in the retrieved results.

    #     Raises:
    #         Exception: If an error occurs during the generation of the PDF report.

    #     """
    #     try:
    #         results = self.dataHandler.getScanResults(1)
    #         pdf.generatePdfReport("default", results)
    #     except Exception as e:
    #         logger.error(f"{str(e)}")
