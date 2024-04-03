from deltascan.core.scanner import Scanner
import deltascan.core.store as store
from deltascan.core.config import (
    CONFIG_FILE_PATH,
    Config,
    ADDED,
    CHANGED,
    REMOVED)
from deltascan.core.exceptions import (DScanInputValidationException,
                                       DScanRDBMSException,
                                       DScanRDBMSEntryNotFound,
                                       DScanResultsSchemaException,
                                       DScanImportFileExtensionError,
                                       DScanSchemaException)
from deltascan.core.utils import (datetime_validation,
                                  validate_host,
                                  check_root_permissions,
                                  n_hosts_on_subnet,
                                  validate_port_state_type,
                                  diffs_to_output_format)
from deltascan.core.export import Exporter
from deltascan.core.schemas import (DBScan, ConfigSchema)
from deltascan.core.importer import Importer

from marshmallow  import ValidationError

import logging
import os
import yaml
import json
import copy

class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing results, and generating reports.
    """
    def __init__(self, config, ui_context=None):
        """
        Initializes a new instance of the Main class.

        Args:
            config (dict): A dictionary containing the configuration parameters.
            ui_context (object, optional): The UI context object. Defaults to None.
        """
        logging.basicConfig(
            level=logging.INFO,
            filename="error.log",
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)

        _config = ConfigSchema().load(config)
        self.config = Config(
            _config["output_file"],
            _config["single"],
            _config["template_file"],
            _config["import_file"],
            _config["action"],
            _config['profile'],
            _config['conf_file'],
            _config['verbose'],
            _config['n_scans'],
            _config['n_diffs'],
            _config['fdate'],
            _config['tdate'],
            _config['port_type'],
            _config['host']
        )
        self.ui_context = ui_context
        self.store = store.Store(logger=self.logger)
        self.generic_scan_info = {
            "host": self.config.host,
            "arguments": "", 
            "profile_name": self.config.profile
        }

        # TODO: think about not storing these fields at all
        self._ignore_fields_for_diffs = [
            "servicefp"
        ]
    
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

    def port_scan(self):
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
            profile = self._load_profiles_from_file(self.config.conf_file)[self.config.profile]
            self.store.save_profiles({self.config.profile: profile})
            profile_arguments = profile["arguments"]
        except (KeyError, IOError) as e:
            self.logger.warning(f"{str(e)}")
            print(f"Profile {self.config.profile} not found in file. "
                   "Searching for profile in database...")
        try:
            profile = self.store.get_profile(self.config.profile)
            profile_arguments = profile["arguments"]
        except DScanRDBMSEntryNotFound:
            self.logger.error(f"Profile {self.config.profile} not found in database")
            raise DScanRDBMSException("Profile not found in database. Please check your profile name.")
        
        try:
            check_root_permissions()
        except PermissionError as e:
            self.logger.error(e)
            print("You need root permissions to run this program.")
            os._exit(1)
        try:
            if validate_host(self.config.host) is False:
                raise DScanInputValidationException("Invalid host format")

            if "/" in self.config.host:
                print("Scanning ",
                      n_hosts_on_subnet(self.config.host),
                      "hosts. Network: ", self.config.host)

            results = Scanner.scan(self.config.host, profile_arguments, self.ui_context, logger=self.logger)
            _new_scans = self.store.save_scans(
                self.config.profile,
                "" if len(self.config.host.split("/")) else self.config.host.split("/")[1], # Subnet
                results,
                profile_arguments
            )

            _new_scan_uuids = [_s.uuid for _s in list(_new_scans)]
            last_n_scans = self.store.get_filtered_scans(_new_scan_uuids)

            if self.config.output_file is not None:
                self._report_scans(last_n_scans)

            return last_n_scans
        except (ValueError, DScanResultsSchemaException) as e:
            self.logger.error(f"{str(e)}")
            raise DScanSchemaException("An error occurred during the scan. Please check your host and arguments.")
    
    def compare(self):
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
            if datetime_validation(self.config.fdate) is False:
                raise DScanInputValidationException("Invalid date format")

            scans = self.store.get_last_n_scans_for_host(
                self.config.host,
                self.config.n_scans,
                self.config.profile,
                from_date=self.config.fdate,
                to_date=self.config.tdate
            )

            diffs = self._list_scans_with_diffs(scans)
            self._report_diffs(diffs)
            return diffs
        except DScanRDBMSEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            print(f"No scan results found for host {self.config.host}")
        except DScanResultsSchemaException as e:
            self.logger.error(f"{str(e)}")
            raise DScanSchemaException("Invalid scan results schema")

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
            if i == len(scans) or len(scan_list_diffs) == self.config.n_diffs:
                break
            if scans[i-1]["result_hash"] != scans[i]["result_hash"]:
                try:
                    scan_list_diffs.append(
                        {
                            "ids": [
                                scans[i-1]["id"],
                                scans[i]["id"]],
                            "uuids": [
                                scans[i-1]["uuid"],
                                scans[i]["uuid"]],
                            "generic": {
                                "host": scans[i-1]["host"],
                                "arguments": scans[i-1]["arguments"], 
                                "profile_name": scans[i-1]["profile_name"]
                            },
                            "dates": [
                                str(scans[i-1]["created_at"]),
                                str(scans[i]["created_at"])],
                            "diffs": self._diffs_between_dicts(
                                self._results_to_port_dict(scans[i-1]),
                                self._results_to_port_dict(scans[i])),
                            "result_hashes": [
                                scans[i-1]["result_hash"],
                                scans[i]["result_hash"]]
                        }
                    )
                except DScanResultsSchemaException as e:
                    self.logger.error(f"{str(e)}")
                    raise DScanSchemaException("Invalid scan results schema given to diffs method")
        return scan_list_diffs
    
    def _results_to_port_dict(self, results):
        """
        Converts the scan results to a dictionary.
        Returns:
            dict: The scan results as a dictionary.
        """

        try:
            DBScan().load(results)
        except (KeyError, ValidationError) as e:
            self.logger.error(f"{str(e)}")
            raise DScanResultsSchemaException("Invalid scan results schema")

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
        # TODO: transfer this method in the utils functions
        diffs = {
            ADDED: {},
            "removed": {},
            CHANGED: {}
        }

        for key in changed_scan:
            if key in self._ignore_fields_for_diffs:
                continue
            if key in old_scan:
                if json.dumps(changed_scan[key]) != json.dumps(old_scan[key]) and \
                    isinstance(changed_scan[key], dict) and isinstance(old_scan[key], dict):
                    diffs[CHANGED][key] = self._diffs_between_dicts(changed_scan[key], old_scan[key]) 
                else:
                    if changed_scan[key] != old_scan[key]:
                        diffs[CHANGED][key] = {"from": old_scan[key], "to": changed_scan[key]}
            else:
                diffs[ADDED][key] = changed_scan[key]

        for key in old_scan:
            if key in self._ignore_fields_for_diffs:
                continue
            if key not in changed_scan:
                diffs[REMOVED][key] = old_scan[key]

        return diffs

    def view(self):
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
            if self.config.fdate is not None and datetime_validation(self.config.fdate) is False:
                raise DScanInputValidationException("Invalid date format")
            
            if self.config.port_type is not None and validate_port_state_type(self.config.port_type.split(",")) is False:
                raise DScanInputValidationException("Invalid port status type")

            scans = self.store.get_filtered_scans(
                    host=self.config.host,
                    last_n=self.config.n_scans,
                    profile=self.config.profile,
                    to_date=self.config.tdate,
                    from_date=self.config.fdate,
                    pstate=self.config.port_type
                )
            self._report_scans(scans)
            return scans
        except DScanRDBMSEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            print(f"No scan results found for host {self.config.host}")

    def import_data(self):
        """
        Import scan results from a file.

        Args:
            import_file (str): The path to the file to import.

        Returns:
            None

        Raises:
            FileNotFoundError: If the file specified by `import_file` does not exist.
            DScanResultsSchemaException: If the scan results schema is invalid.
        """
        try:
            _importer = Importer(self.config.import_file, logger=self.logger)

            return _importer.import_data()
        except( FileNotFoundError, NotImplementedError) as e:
            self.logger.error(f"{str(e)}")
            print(f"File {self.config.import_file} not found")

    def _report_diffs(self, diffs): # TODO: NOO. create class object with all the information about host, profile, arguments etc
        """
        Generate a report based on the differences between two scan results.

        Args:
            diffs (list): A list of dictionaries containing the differences between two scan results.

        Returns:
            None
        """
        try:
            articulated_diffs = []
            for diff in diffs:
                articulated_diffs.append(
                    {"date_from": diff["dates"][1],
                     "date_to": diff["dates"][0],
                     "diffs": diffs_to_output_format(diff),
                     "generic": diff["generic"],
                     "uuids": diff["uuids"]})
        except DScanResultsSchemaException as e:
            self.logger.error(f"{str(e)}")
            raise DScanSchemaException("Could not handle diffs schema")
        if self.config.output_file is not None:
            reporter = Exporter(
                articulated_diffs,
                self.config.output_file,
                self.config.template_file,
                single=self.config.single,
                logger=self.logger
            )
            reporter.export()
        

    def _report_scans(self, scans):
        """
        Generate a report based on the scan results.

        Args:
            scans (list): A list of scan results.

        Returns:
            None
        """
        try:
            DBScan(many=True).load(scans)
        except (KeyError, ValidationError) as e:
            self.logger.error(f"{str(e)}")
            raise DScanResultsSchemaException("Invalid scan results schema")
        if self.config.output_file is not None:
            reporter = Exporter(
                scans,
                self.config.output_file,
                self.config.template_file,
                single=self.config.single,
                logger=self.logger
            )
    
            reporter.export()