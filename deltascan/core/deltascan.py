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
                                       DScanExporterFileExtensionNotSpecified,
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
import signal

class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing result, and generating reports.
    """
    def __init__(self, config, ui_context=None, result=None):
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
        self._result = result

        _config = ConfigSchema().load(config)
        self._config = Config(
            _config["is_interactive"],
            _config["output_file"],
            _config["single"],
            _config["template_file"],
            _config["import_file"],
            _config["action"],
            _config['profile'],
            _config['conf_file'],
            _config['verbose'],
            _config['suppress'],
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
            "host": self._config.host,
            "arguments": "", 
            "profile_name": self._config.profile
        }

        # TODO: think about not storing these fields at all
        self._ignore_fields_for_diffs = [
            "servicefp"
        ]
    
    def _load_profiles_from_file(self, path=None):
        """
        Load profiles from a YAML file.

        Args:
            path (str, optional): The path to the YAML file. If not provided, the default path will be used.

        Returns:
            dict: A dictionary containing the loaded profiles.
        """

        yaml_file_path = CONFIG_FILE_PATH if path is None else path

        with open(yaml_file_path, "r") as file:
            data = yaml.safe_load(file)

        return data["profiles"]

    def port_scan(self):
        """
        Perform a port scan using the specified profile and host.

        Returns:
            A list of the last n scans performed.

        Raises:
            DScanRDBMSException: If the profile is not found in the database.
            PermissionError: If root permissions are required to run the program.
            DScanInputValidationException: If the host format is invalid.
            DScanSchemaException: If an error occurs during the scan.
        """
        
        try:
            profile = self._load_profiles_from_file(self._config.conf_file)[self._config.profile]
            self.store.save_profiles({self._config.profile: profile})
            profile_arguments = profile["arguments"]
        except (KeyError, IOError) as e:
            self.logger.warning(f"{str(e)}")
            print(f"Profile {self._config.profile} not found in file. "
                    "Searching for profile in database...")
        try:
            profile = self.store.get_profile(self._config.profile)
            profile_arguments = profile["arguments"]
        except DScanRDBMSEntryNotFound:
            self.logger.error(f"Profile {self._config.profile} not found in database")
            raise DScanRDBMSException("Profile not found in database or in file. Please check your profile name or give a valid configuration file.")
        
        try:
            check_root_permissions()
        except PermissionError as e:
            self.logger.error(e)
            print("You need root permissions to run this program.")
            os._exit(1)
        try:
            if validate_host(self._config.host) is False:
                raise DScanInputValidationException("Invalid host format")

            if "/" in self._config.host:
                print("Scanning ",
                        n_hosts_on_subnet(self._config.host),
                        "hosts. Network: ", self._config.host)

            results = Scanner.scan(self._config.host, profile_arguments, self.ui_context, logger=self.logger)

            _new_scans = self.store.save_scans(
                self._config.profile,
                "" if len(self._config.host.split("/")) else self._config.host.split("/")[1], # Subnet
                results,
                profile_arguments
            )

            _new_scan_uuids = [_s.uuid for _s in list(_new_scans)]
            last_n_scans = self.store.get_filtered_scans(
                    _new_scan_uuids,
                    last_n=len(_new_scan_uuids))

            if self._config.output_file is not None:
                self._report_scans(last_n_scans)

            self._result["scans"] = last_n_scans
            self._result["finished"] = True

            return last_n_scans
        except (ValueError, DScanResultsSchemaException) as e:
            self.logger.error(f"{str(e)}")
            if self._config.is_interactive == True:
                print("An error occurred during the scan. Please check your host and arguments.")
            else:
                raise DScanSchemaException("An error occurred during the scan. Please check your host and arguments.")
                
    
    def diffs(self, uuids=None):
        """
        Compares the scans for a given host within a specified date range.

        Returns:
            list: A list of scan differences.

        Raises:
            DScanInputValidationException: If the date format is invalid.
            DScanRDBMSEntryNotFound: If no scan results are found for the host.
            DScanResultsSchemaException: If the scan results schema is invalid.
        """
        try:
            if datetime_validation(self._config.fdate) is False:
                if self._config.is_interactive == True:
                    print("Invalid date format. Using default date range.")
                else:
                    raise DScanInputValidationException("Invalid date format")

            scans = self.store.get_filtered_scans(
                uuid=uuids,
                host=self._config.host,
                last_n=self._config.n_scans,
                profile=self._config.profile,
                from_date=self._config.fdate,
                to_date=self._config.tdate
            )

            diffs = self._list_scans_with_diffs(scans)
            self._report_diffs(diffs)

            self._result["diffs"] = diffs
            self._result["finished"] = True

            return diffs
        except DScanRDBMSEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            print(f"No scan results found for host {self._config.host}")
        except DScanResultsSchemaException as e:
            self.logger.error(f"{str(e)}")
            if self._config.is_interactive == True:
                print("Invalid scan results schema")
            else:
                raise DScanSchemaException("Invalid scan results schema")

    def _list_scans_with_diffs(self, scans):
        """
        Returns a list of scans with differences between consecutive scans.

        Args:
            scans (list): A list of scan dictionaries.

        Returns:
            list: A list of scan dictionaries with differences between consecutive scans.
        """
        scan_list_diffs = []
        for i, _ in enumerate(scans, 1):
            if i == len(scans) or len(scan_list_diffs) == self._config.n_diffs:
                break
            if scans[i-1]["result_hash"] != scans[i]["result_hash"] and scans[i-1]["results"] != scans[i]["results"]:
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
                    if self._config.is_interactive == True:
                        print("Invalid scan results schema given to diffs method")
                    else:
                        raise DScanSchemaException("Invalid scan results schema given to diffs method")
        return scan_list_diffs
    
    def _results_to_port_dict(self, results):
        """
        Convert the scan results to a dictionary format.

        Args:
            results (dict): The scan results.

        Returns:
            dict: The converted port dictionary.

        Raises:
            DScanResultsSchemaException: If the scan results have an invalid schema.
        """

        try:
            DBScan().load(results)
        except (KeyError, ValidationError) as e:
            self.logger.error(f"{str(e)}")
            if self._config.is_interactive == True:
                print("Invalid scan results schema")
            else:
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
        Calculate the differences between two dictionaries.

        This method compares two dictionaries, `changed_scan` and `old_scan`, and identifies the differences between them.
        It returns a dictionary containing the added, removed, and changed keys and their corresponding values.

        Args:
            changed_scan (dict): The dictionary representing the changed scan.
            old_scan (dict): The dictionary representing the old scan.

        Returns:
            dict: A dictionary containing the added, removed, and changed keys and their corresponding values.

        """
        # TODO: transfer this method in the utils functions
        diffs = {
            ADDED: {},
            REMOVED: {},
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
        Retrieves and filters scans based on the provided configuration.

        Returns:
            list: A list of filtered scans.

        Raises:
            DScanInputValidationException: If the provided date format or port status type is invalid.
            DScanRDBMSEntryNotFound: If no scan results are found for the specified host.
        """
        try:
            if self._config.fdate is not None and datetime_validation(self._config.fdate) is False:
                raise DScanInputValidationException("Invalid date format")
            
            if self._config.port_type is not None and validate_port_state_type(self._config.port_type.split(",")) is False:
                raise DScanInputValidationException("Invalid port status type")

            scans = self.store.get_filtered_scans(
                    host=self._config.host,
                    last_n=self._config.n_scans,
                    profile=self._config.profile,
                    to_date=self._config.tdate,
                    from_date=self._config.fdate,
                    pstate=self._config.port_type
                )
            self._report_scans(scans)

            self._result["scans"] = scans
            self._result["finished"] = True

            return scans
        except DScanRDBMSEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            print(f"No scan results found for host {self._config.host}")

    def import_data(self):
        """
        Imports data from a file specified in the configuration.
        
        Returns:
            The imported data.
        
        Raises:
            FileNotFoundError: If the specified file is not found.
            NotImplementedError: If the method is not implemented.
        """
        try:
            _importer = Importer(self._config.import_file, logger=self.logger)

            return _importer.import_data()
        except( FileNotFoundError, NotImplementedError) as e:
            self.logger.error(f"{str(e)}")
            print(f"File {self._config.import_file} not found")

    def _report_diffs(self, diffs, output_file=None):
        """
        Reports the differences between two dates.

        Args:
            diffs (list): A list of differences between two dates.

        Raises:
            DScanSchemaException: If the diffs schema cannot be handled.

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
            if self._config.is_interactive == True:
                print("Could not handle diffs schema.")
            else:
                raise DScanSchemaException("Could not handle diffs schema.")
        if self._config.output_file is not None or output_file is not None:
            try:
                reporter = Exporter(
                    articulated_diffs,
                    self._config.output_file if output_file is None else output_file,
                    self._config.template_file,
                    single=self._config.single,
                    logger=self.logger
                )
                reporter.export()
            except DScanExporterFileExtensionNotSpecified as e:
                if self._config.is_interactive == True:
                    print(f"Filename error: {str(e)}")
                else:
                    raise DScanResultsSchemaException(f"Filename error: {str(e)}")
        else:
            if self._config.is_interactive == True:
                print("File not provided. Diff report was not generated")
  
    def _report_scans(self, scans, output_file=None):
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
            if self._config.is_interactive == True:
                print("Invalid scan results schema")
            else:
                raise DScanResultsSchemaException("Invalid scan results schema")
        if self._config.output_file is not None or output_file is not None:
            try:
                reporter = Exporter(
                    scans,
                    self._config.output_file if output_file is None else output_file,
                    self._config.template_file,
                    single=self._config.single,
                    logger=self.logger
                )
        
                reporter.export()
            except DScanExporterFileExtensionNotSpecified as e:
                if self._config.is_interactive == True:
                    print(f"Filename error: {str(e)}")
                else:
                    raise DScanResultsSchemaException(f"Filename error: {str(e)}")
        else:
            if self._config.is_interactive == True:
                print("File not provided. Scan report was not generated")

    def report_result(self):
            """
            Generates a report for the scans if they are finished and available.

            This method checks if the scans are finished and not None, and then calls the _report_scans method
            to generate a report for the scans.

            Returns:
                None
            """
            if self._result["finished"] is True and self._result["scans"] is not None and self._config.output_file is not None:
                self._report_scans(self._result["scans"], "scans_" + self._config.output_file)

            if self._result["finished"] is True and self._result["diffs"] is not None and self._config.output_file is not None:
                self._report_diffs(self._result["diffs"], "diffs_" + self._config.output_file)

    def stored_scans_count(self):
        """
        Returns the number of stored scans.

        Returns:
            int: The number of stored scans.
        """
        return self.store.get_scans_count()

    def stored_profiles_count(self):
        """
        Returns the number of stored scans.

        Returns:
            int: The number of stored scans.
        """
        return self.store.get_profiles_count()

    @property
    def output_file(self):
        return self._config.output_file

    @output_file.setter
    def output_file(self, value):
        self._config.output_file = value

    @property
    def template_file(self):
        return self._config.template_file

    @template_file.setter
    def template_file(self, value):
        self._config.template_file = value

    @property
    def import_file(self):
        return self._config.import_file

    @import_file.setter
    def import_file(self, value):
        self._config.import_file = value

    @property
    def n_scans(self):
        return self._config.n_scans

    @n_scans.setter
    def n_scans(self, value):
        self._config.n_scans = value

    @property
    def n_diffs(self):
        return self._config.n_diffs

    @n_diffs.setter
    def n_diffs(self, value):
        self._config.n_diffs = value

    @property
    def fdate(self):
        return self._config.fdate

    @fdate.setter
    def fdate(self, value):
        self._config.fdate = value

    @property
    def tdate(self):
        return self._config.tdate

    @tdate.setter
    def tdate(self, value):
        self._config.tdate = value

    @property
    def is_interactive(self):
        return self._config.is_interactive

    @is_interactive.setter
    def is_interactive(self, value):
        self._config.is_interactive = value

    @property
    def suppress(self):
        return self._config.suppress

    @suppress.setter
    def suppress(self, value):
        self._config.suppress = value

    @property
    def host(self):
        return self._config.host

    @host.setter
    def host(self, value):
        if self._result["finished"] == True:
            self._config.host = value

    @property
    def profile(self):
        return self._config.profile

    @profile.setter
    def profile(self, value):
        if self._result["finished"] == True:
            self._config.profile = value

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value):
        self._result = value


