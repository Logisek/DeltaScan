from deltascan.core.scanner import Scanner
import deltascan.core.store as store
from deltascan.core.config import (
    CONFIG_FILE_PATH,
    Config,
    ADDED,
    CHANGED,
    REMOVED)
from deltascan.core.exceptions import (DScanInputValidationException,
                                       DScanRDBMSEntryNotFound,
                                       DScanResultsSchemaException,
                                       DScanExporterFileExtensionNotSpecified,
                                       DScanSchemaException)
from deltascan.core.utils import (datetime_validation,
                                  validate_host,
                                  check_root_permissions,
                                  validate_port_state_type,
                                  diffs_to_output_format)
from deltascan.core.export import Exporter
from deltascan.core.schemas import (DBScan, ConfigSchema)
from deltascan.core.importer import Importer

from marshmallow import ValidationError

from threading import Thread, Event
import logging
import os
import yaml
import json
import copy
import time

from rich.progress import (
    BarColumn,
    Progress,
    TextColumn)
from rich.text import Text
from rich.columns import Columns


class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing result, and generating reports.
    """
    def __init__(self, config, ui_context=None, result=[]):
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
        self._scan_list = []
        self._scans_to_wait = {}
        self._names_of_scans = []
        self.renderables = []
        self._cleaning_up = False
        self._is_running = False

        self._T = None

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
            "servicefp",
            "osfingerprint",
            "host"
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

    def add_scan(self, host=None, profile=None):
        """
        Add a new scan to the DeltaScan instance.

        Args:
            host (str): The host to scan.
            profile (str): The profile to use for the scan.

        Returns:
            bool: True if the scan was successfully added, False otherwise.
        """
        _name = f"scan-{str(host)}-{str(profile)}"
        if _name in self._names_of_scans or self._get_profile(profile) == (None, None) or validate_host(host) is False:
            return False
        self._names_of_scans.append(_name)
        self._scan_list.append({"host": host, "profile": profile, "name": _name})

        progress_bar = Progress(
            TextColumn(f"[bold light_slate_gray]Scanning: host -> {host}, profile -> {profile}", justify="right"),
            BarColumn(complete_style="green"),
            TextColumn("[progress.percentage][light_slate_gray]{task.percentage:>3.1f}%"))

        progress_bar_id = progress_bar.add_task("", total=100)
        progress_bar.update(progress_bar_id, advance=1)

        text = Text(no_wrap=True, overflow="fold", style="dim light_slate_gray")
        text.stylize("bold magenta", 0, 6)
        _coltmp = Columns([progress_bar], equal=True)
        self.renderables.append(_coltmp)
        col = Columns(self.renderables, equal=True)
        if "progress_bar" not in self.ui_context["ui_instances"]:
            self.ui_context["ui_instances"]["progress_bar"] = {}
        if "text" not in self.ui_context["ui_instances"]:
            self.ui_context["ui_instances"]["text"] = {}

        if str(_name) not in self.ui_context["ui_instances"]["progress_bar"]:
            self.ui_context["ui_instances"]["progress_bar"][str(_name)] = {}

        if str(_name) not in self.ui_context["ui_instances"]["text"]:
            self.ui_context["ui_instances"]["text"][str(_name)] = {}
        self.ui_context["ui_live"].update(col)
        self.ui_context["ui_instances"]["progress_bar"][str(_name)]["instance"] = progress_bar
        self.ui_context["ui_instances"]["progress_bar"][str(_name)]["id"] = progress_bar_id
        self.ui_context["ui_instances"]["text"][str(_name)]["instance"] = text

        return True

    def scan(self):
        """
        Starts the scan process by creating a new thread and calling the _scan_orchestrator method.
        This method will start the scan asynchronously and wait for it to complete before returning.

        Returns:
            None
        """
        if self._is_running == True:
            return
        self._T = Thread(target=self._scan_orchestrator)
        self._T.start()
        self._T.join()

    def _scan_orchestrator(self):
        self._scans_to_wait = {}
        
        self._is_running = True
        while True:
            self._remove_finished_scan_from_list()
            if self.scans_to_wait == 0 and self.scans_to_execute == 0:
                time.sleep(2)
                if self.scans_to_wait == 0 and self.scans_to_execute == 0:
                    self._is_running = False
                    break
                continue

            for _, _scan in enumerate(self._scan_list):
                _evt = Event()
                _thr = Thread(target=self._port_scan, args=(_scan["host"], _scan["profile"], _scan["name"], _evt,))
                _thr.start()

                for idx, _scan_s in enumerate(self._scan_list):
                    if _scan["name"] == _scan_s["name"]:
                        del self._scan_list[idx]
                        break
                self._scans_to_wait[str(_scan["name"])] = {"_thr": _thr, "_cancel_event": _evt}
            time.sleep(1)

    def _remove_finished_scan_from_list(self):
            """
            Removes the finished scans from the list of scans to wait for completion.

            This method iterates over the `_scans_to_wait` dictionary and checks if each thread is alive.
            If a thread is not alive, it is removed from the dictionary.

            Args:
                None

            Returns:
                None
            """
            threads_to_remove = []
            for _n, _th in self._scans_to_wait.items():
                if _th["_thr"].is_alive() is False:
                    threads_to_remove.append(_n)
            for _n in threads_to_remove:
                del self._scans_to_wait[_n]

    def _get_profile(self, _profile):
        try:
            profile = self.store.get_profile(_profile)
            profile_arguments = profile["arguments"]
        except DScanRDBMSEntryNotFound:
            self.logger.error(f"Profile {_profile} not found in database")

        try:
            profile_from_file = self._load_profiles_from_file(self._config.conf_file)[_profile]
            self.store.save_profiles({_profile: profile_from_file})
            profile_arguments = profile_from_file["arguments"]
        except (KeyError, IOError) as e:
            self.logger.warning(f"{str(e)}")
            self.logger.error(f"Profile {_profile} neither in database or file.")
            return (None, None)
        return (_profile, profile_arguments)

    def _port_scan(self, __host=None, __profile=None, __name=None, __evt=None):
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
        _host = __host if __host is not None else self._config.host
        _profile = __profile if __profile is not None else self._config.profile
        _name = __name if __name is not None else f"scan-{_host}-{_profile}"

        _profile, _profile_arguments = self._get_profile(_profile)

        try:
            check_root_permissions()
        except PermissionError as e:
            self.logger.error(e)
            print("You need root permissions to run this program.")
            os._exit(1)
        try:
            if validate_host(_host) is False:
                raise DScanInputValidationException("Invalid host format")

            results = Scanner.scan(_host, _profile_arguments, self.ui_context, logger=self.logger, name=_name, _cancel_evt=__evt)

            if results is None:
                return None

            _new_scans = self.store.save_scans(
                _profile,
                _host,  # Subnet
                results
            )

            _new_scan_uuids = [_s.uuid for _s in list(_new_scans)]
            last_n_scans = self.store.get_filtered_scans(
                    _new_scan_uuids,
                    last_n=len(_new_scan_uuids))

            if self._config.output_file is not None:
                self._report_scans(last_n_scans, f"scans_{_host}_{_profile}_{self._config.output_file}")

            self._result.append({
                "scans": last_n_scans,
                "host": _host,
                "profile": _profile,
                "finished": True
            })

            return last_n_scans
        except (ValueError, DScanResultsSchemaException) as e:
            self.logger.error(f"{str(e)}")
            if self._config.is_interactive is True:
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
                if self._config.is_interactive is True:
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

            _split_scans_in_hosts = {}
            for _s in scans:
                if _s["results"]["host"] not in _split_scans_in_hosts:
                    _split_scans_in_hosts[_s["results"]["host"]] = []
                _split_scans_in_hosts[_s["results"]["host"]].append(_s)

            diffs = self._list_scans_with_diffs([_s for _scans in _split_scans_in_hosts.values() for _s in _scans])
            if self._config.output_file is not None:
                self._report_diffs(diffs, output_file=f"diffs_{self._config.output_file}")

            self._result.append({
                "diffs": diffs,
                "finished": True
            })

            return diffs
        except DScanRDBMSEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            print(f"No scan results found for host {self._config.host}")
        except DScanResultsSchemaException as e:
            self.logger.error(f"{str(e)}")
            if self._config.is_interactive is True:
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
            if (scans[i-1]["result_hash"] != scans[i]["result_hash"] or scans[i-1]["results"] !=
                    scans[i]["results"]) and scans[i-1]["results"]["host"] == scans[i]["results"]["host"]:
                try:
                    scan_list_diffs.append(
                        {
                            "ids": [
                                scans[i-1]["id"],
                                scans[i]["id"]],
                            "uuids": [
                                scans[i-1]["uuid"],
                                scans[i]["uuid"]],
                            "generic": [
                                {
                                    "host": scans[i-1]["results"]["host"],
                                    "arguments": scans[i-1]["arguments"],
                                    "profile_name": scans[i-1]["profile_name"]
                                },
                                {
                                    "host": scans[i]["results"]["host"],
                                    "arguments": scans[i]["arguments"],
                                    "profile_name": scans[i]["profile_name"]
                                }
                            ],
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
                    if self._config.is_interactive is True:
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
            if self._config.is_interactive is True:
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
            ADDED: self.__find_added(changed_scan, old_scan),
            REMOVED: self.__find_removed(changed_scan, old_scan),
            CHANGED: self.__find_changed(changed_scan, old_scan)
        }

        return diffs

    def __find_added(self, changed_scan, old_scan):
        """
        Recursively compares two dictionaries `changed_scan` and `old_scan` to find added fields.

        Args:
            changed_scan (dict): The dictionary representing the changed scan.
            old_scan (dict): The dictionary representing the old scan.

        Returns:
            dict: A dictionary containing the added fields in `changed_scan` compared to `old_scan`.
        """
        diffs = {}
        for key in changed_scan:
            if key in self._ignore_fields_for_diffs:
                continue
            if key in old_scan:
                if json.dumps(changed_scan[key]) != json.dumps(old_scan[key]) and \
                        isinstance(changed_scan[key], dict) and isinstance(old_scan[key], dict):
                    _added = self.__find_added(changed_scan[key], old_scan[key])
                    if _added != {} and _added is not None:
                        diffs[key] = _added
            else:
                diffs[key] = "-"
        return diffs

    def __find_changed(self, changed_scan, old_scan):
        """
        Recursively compares two dictionaries and returns the differences between them.

        Args:
            changed_scan (dict): The dictionary representing the changed scan.
            old_scan (dict): The dictionary representing the old scan.

        Returns:
            dict: A dictionary containing the differences between the two scans.
                  The keys represent the fields that have changed, and the values
                  represent the changes made. If a field is a nested dictionary,
                  the differences within that dictionary are also included.

        """
        diffs = {}
        for key in changed_scan:
            if key in self._ignore_fields_for_diffs:
                continue
            if key in old_scan:
                if json.dumps(changed_scan[key]) != json.dumps(old_scan[key]) and \
                        isinstance(changed_scan[key], dict) and isinstance(old_scan[key], dict):
                    diffs[key] = self.__find_changed(changed_scan[key], old_scan[key])
                else:
                    if changed_scan[key] != old_scan[key]:
                        diffs[key] = {"from": old_scan[key], "to": changed_scan[key]}
        return diffs

    def __find_removed(self, changed_scan, old_scan):
        """
        Recursively compares two dictionaries, `changed_scan` and `old_scan`, and returns a dictionary
        containing the differences between them. The differences are identified by finding keys that exist
        in `old_scan` but not in `changed_scan`.

        Args:
            changed_scan (dict): The updated dictionary.
            old_scan (dict): The original dictionary.

        Returns:
            dict: A dictionary containing the differences between `changed_scan` and `old_scan`.
        """
        diffs = {}
        for key in old_scan:
            if key in self._ignore_fields_for_diffs:
                continue
            if key in changed_scan:
                if json.dumps(changed_scan[key]) != json.dumps(old_scan[key]) and \
                        isinstance(changed_scan[key], dict) and isinstance(old_scan[key], dict):
                    _removed = self.__find_removed(changed_scan[key], old_scan[key])
                    if _removed != {} and _removed is not None:
                        diffs[key] = _removed
            else:
                diffs[key] = "_"
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
                    pstate=self._config.port_type)

            return scans
        except DScanRDBMSEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            print(f"No scan results found for host {self._config.host}")

    def import_data(self, __filename):
        """
        Imports data from a file specified in the configuration.

        Returns:
            The imported data.

        Raises:
            FileNotFoundError: If the specified file is not found.
            NotImplementedError: If the method is not implemented.
        """
        _filename = __filename if __filename is not None else self._config.import_file
        try:
            _importer = Importer(_filename, logger=self.logger)

            return _importer.import_data()
        except (FileNotFoundError, NotImplementedError) as e:
            self.logger.error(f"{str(e)}")
            print(f"File {_filename} not found")

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
            if self._config.is_interactive is True:
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
                if self._config.is_interactive is True:
                    print(f"Filename error: {str(e)}")
                else:
                    raise DScanResultsSchemaException(f"Filename error: {str(e)}")
        else:
            if self._config.is_interactive is True:
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
            if self._config.is_interactive is True:
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
                if self._config.is_interactive is True:
                    print(f"Filename error: {str(e)}")
                else:
                    raise DScanResultsSchemaException(f"Filename error: {str(e)}")
        else:
            if self._config.is_interactive is True:
                print("File not provided. Scan report was not generated")

    def report_result(self):
        """
        Generates a report for the scans if they are finished and available.

        This method checks if the scans are finished and not None, and then calls the _report_scans method
        to generate a report for the scans.

        Returns:
            None
        """
        for _res in self._result:
            if _res["finished"] is True and "scans" in _res and _res["scans"] is not None and self._config.output_file is not None:
                self._report_scans(_res["scans"], f"scans_{_res['host']}_{_res['profile']}_{self._config.output_file}")

            if _res["finished"] is True and "diffs" in _res and _res["diffs"] is not None and self._config.output_file is not None:
                self._report_diffs(_res["diffs"], f"diffs_{self._config.output_file}")

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

    def list_profiles(self):
        """
        Lists the available profiles.

        Returns:
            dict: A dictionary containing the available profiles.
        """
        return self.store.get_profiles()

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
        self._config.host = value

    @property
    def profile(self):
        return self._config.profile

    @profile.setter
    def profile(self, value):
        self._config.profile = value

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value):
        self._result = value

    @property
    def is_running(self):
        return self._is_running

    @property
    def scans_to_wait(self):
        return len(self._scans_to_wait.keys())
    
    @property
    def scans_to_execute(self):
        return len(self._scan_list)

    @property
    def cleaning_up(self):
        return self._cleaning_up

    def cleanup(self):
        self._cleaning_up = True
        for _, _th in self._scans_to_wait.items():
            if _th["_thr"].is_alive() is True:
                _th["_cancel_event"].set()
