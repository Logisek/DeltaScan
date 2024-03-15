import deltascan.core.scanner as scanner
import deltascan.core.store as store
from deltascan.core.config import CONFIG_FILE_PATH
from deltascan.core.exceptions import (DScanInputValidationException,
                                       DScanRDBMSException,
                                       DScanException,
                                       DScanRDBMSEntryNotFound,
                                       DScanResultsSchemaException)
from deltascan.core.utils import (datetime_validation,
                                  validate_host,
                                  check_root_permissions,
                                  n_hosts_on_subnet,
                                  validate_port_state_type)
import logging
import os
import yaml
import json
import copy

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

            if "/" in host:
                print("Scanning ",
                      n_hosts_on_subnet(host),
                      "hosts . Network: ", host)

            results = self.scanner.scan(host, profile_arguments)
            self.store.save_scans(
                profile_name,
                "" if len(host.split("/")) else host.split("/")[1], # Subnet
                results,
                profile_arguments
            )

        except (ValueError, DScanResultsSchemaException) as e:
            logger.error(f"{str(e)}")
            raise DScanException("An error occurred during the scan. Please check your host and arguments.")

        return results
    
    def compare(self, host, n_scans, date, profile):
        """
        Compare the scan results for a given host.

        Args:
            host (str): The hostname to compare the scan results for.
            n_scans (int): The number of scans to retrieve.
            date (str): The date to filter the scan results.
            profile (str): The profile to use for the comparison.

        Returns:
            list: A list of scan results with differences.

        Raises:
            DScanInputValidationException: If the date format is invalid.
            DScanRDBMSEntryNotFound: If no scan results are found for the host.
        """
        try:
            if datetime_validation(date) is False:
                raise DScanInputValidationException("Invalid date format")

            scans = self.store.get_last_n_scans_for_host(
                host, n_scans, profile, date
            )
            return self._list_scans_with_diffs(scans)
        except DScanRDBMSEntryNotFound as e:
            logger.error(f"{str(e)}")
            print(f"No scan results found for host {host}")

    def _list_scans_with_diffs(self, scans):
        """
        Lists the scans with differences.

        Args:
            scans (list): A list of scan objects.

        Returns:
            None
        """
        scan_list_diffs = []
        for i, _ in enumerate(scans, 1):
            if i == len(scans):
                break
            if scans[i-1]["result_hash"] != scans[i]["result_hash"]:
                scan_list_diffs.append(
                    {
                        "ids": [
                            scans[i-1]["id"],
                            scans[i]["id"]],
                        "dates": [
                            str(scans[i-1]["created_at"]),
                            str(scans[i]["created_at"])],
                        "diffs": self._diffs_between_dicts(
                            self._results_to_port_dict(scans[i-1]),
                            self._results_to_port_dict(scans[i])),
                        "result_hash": [
                            scans[i-1]["result_hash"],
                            scans[i]["result_hash"]]
                    }
                )

        return scan_list_diffs
    
    def _results_to_port_dict(self, results):
        """
        Converts the scan results to a dictionary.
        Returns:
            dict: The scan results as a dictionary.
        """
        # print(results)
        port_dict = copy.deepcopy(results)

        port_dict["results"]["new_ports"] = {}
        for port in port_dict["results"]["ports"]:
                port_dict["results"]["new_ports"][port["portid"]] = port
        port_dict["results"]["ports"] = port_dict["results"]["new_ports"]
        del port_dict["results"]["new_ports"]

        return port_dict["results"]
    
    def _diffs_between_dicts(self, changed_scan, old_scan):
        """
        Returns the differences between two dictionaries.

        Args:
            dict1 (dict): The first dictionary.
            dict2 (dict): The second dictionary.

        Returns:
            dict: The differences between the two dictionaries.
        """
        diffs = {
            "added": {},
            "removed": {},
            "changed": {}
        }

        for key in changed_scan:
            if key in old_scan:
                if json.dumps(changed_scan[key]) != json.dumps(old_scan[key]) and \
                    isinstance(changed_scan[key], dict) and isinstance(old_scan[key], dict):
                    diffs["changed"][key] = self._diffs_between_dicts(changed_scan[key], old_scan[key]) 
                else:
                    if changed_scan[key] != old_scan[key]:
                        diffs["changed"][key] = {"from": old_scan[key], "to": changed_scan[key]}
            else:
                diffs["added"][key] = changed_scan[key]

        for key in old_scan:
            if key not in old_scan:
                diffs["removed"][key] = old_scan[key]

        return diffs

    # def _categorize_deltas(self, scans):
    #     """
    #     Categorizes the deltas based on profile name and result hash.

    #     Args:
    #         scans (list): A list of scan objects.

    #     Returns:
    #         dict: A dictionary containing the categorized deltas.
    #             The keys of the dictionary are the profile names.
    #             The values of the dictionary are dictionaries where the keys are the result hashes
    #             and the values are lists of scan IDs.
    #     """
    #     similar_scan_ids = {}
    #     hash_order = []
    #     for i in range(len(scans)):
    #         if str(scans[i]["profile_name"]) not in similar_scan_ids:
    #             similar_scan_ids[str(scans[i]["profile_name"])] = {}
                
    #         if scans[i]["result_hash"] not in similar_scan_ids[str(scans[i]["profile_name"])]:
    #             similar_scan_ids[str(scans[i]["profile_name"])][scans[i]["result_hash"]] = []
    #             hash_order.append(scans[i]["result_hash"])

    #         similar_scan_ids[str(scans[i]["profile_name"])][scans[i]["result_hash"]].append(scans[i]["id"])
    #     return similar_scan_ids
        

    def view(self, host, n_scans, date, profile, pstate):
        """
        Retrieve filtered scan results based on the provided parameters.

        Args:
            host (str): The host for which to retrieve scan results.
            n_scans (int): The number of latest scans to retrieve.
            date (str): The date in the format 'YYYY-MM-DD' to filter the scan results.
            profile (str): The profile to filter the scan results.
            pstate (str): The port status type to filter the scan results. Multiple types can be provided separated by commas.

        Returns:
            list: A list of filtered scan results.

        Raises:
            DScanInputValidationException: If the date format or port status type is invalid.
            DScanRDBMSEntryNotFound: If no scan results are found for the specified host.
        """
        try:
            if date is not None and datetime_validation(date) is False:
                raise DScanInputValidationException("Invalid date format")
            
            if pstate is not None and validate_port_state_type(pstate.split(",")) is False:
                raise DScanInputValidationException("Invalid port status type")

            return self.store.get_filtered_scans(
                    host=host, last_n=n_scans, profile=profile, creation_date=date, pstate=pstate
                )
        except DScanRDBMSEntryNotFound as e:
            logger.error(f"{str(e)}")
            print(f"No scan results found for host {host}")
