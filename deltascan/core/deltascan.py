from deltascan.core.scanner import Scanner
import deltascan.core.store as store
from deltascan.core.config import (
    CONFIG_FILE_PATH,
    FILE_DATE_FORMAT,
    APP_DATE_FORMAT,
    Config,
    ADDED,
    CHANGED,
    REMOVED)
from deltascan.core.exceptions import (AppExceptions,
                                       StoreExceptions,
                                       ExporterExceptions,
                                       ImporterExceptions)
from deltascan.core.utils import (datetime_validation,
                                  validate_host,
                                  check_root_permissions,
                                  validate_port_state_type,
                                  ThreadWithException)
from deltascan.core.export import Exporter
from deltascan.core.schemas import (DBScan, ConfigSchema, Scan)
from deltascan.core.importer import Importer
from deltascan.core.parser import Parser
from marshmallow import ValidationError

from threading import Event
import logging
import os
import yaml
import json
import copy
import time
from datetime import datetime

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
        error_log = "error.log"

        try:
            logging.basicConfig(
                level=logging.INFO,
                filename=error_log,
                format="%(asctime)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        except PermissionError:
            raise AppExceptions.DScanAppError(
                f"{error_log} file belongs to root. Please change the owner to a non-root user.")

        self.logger = logging.getLogger(__name__)
        self._result = result
        self._scan_list = []
        self._scans_to_wait = {}
        self._scans_history = []
        self.renderables = []
        self._cleaning_up = False
        self._has_been_interactive = False
        self._is_running = False

        self._T = None

        _config = ConfigSchema().load(config)
        self._config = Config(
            _config["is_interactive"],
            _config["output_file"],
            _config["single"],
            _config["template_file"],
            _config["import_file"],
            _config["diff_files"],
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
            _config['host'],
            _config['db_path']
        )
        self.ui_context = ui_context

        try:
            self.store = store.Store(self._config.db_path, logger=self.logger)
        except StoreExceptions.DScanPermissionError:
            raise AppExceptions.DScanAppError(
                f"{error_log} file belongs to root. Please change the owner to a non-root user.")

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
        Add a scan to the DeltaScan instance.

        Args:
            host (str): The host to scan.
            profile (str): The profile to use for the scan.

        Raises:
            AppExceptions.DScanProfileNotFoundException: If the profile is not found or the host is invalid.
            AppExceptions.DScanInputValidationException: If the scan name already exists.

        Returns:
            bool: True if the scan was successfully added.
        """
        _name = f"scan-{str(host)}-{str(profile)}"
        if _name in self._scans_to_wait.keys():
            raise AppExceptions.DScanInputValidationException("Scan is already running")

        if self._get_profile(profile) == (None, None):
            raise AppExceptions.DScanProfileNotFoundException(f"Profile {profile} not found anywhere.")
        if validate_host(host) is False:
            raise AppExceptions.DScanInputValidationException("Invalid host format")

        self._scan_list.append({"host": host, "profile": profile, "name": _name})

        _c = 0
        count = ""
        for _s in self._scans_history:
            if _s.startswith(_name):
                _c = _c + 1
        if _c > 0:
            count = f"- ({str(_c)})"

        progress_bar = Progress(
            TextColumn(f"{'[bold light_slate_gray]Scanning: ' + host + ', ' + profile + ' ' + count:<20}", justify="right"),
            BarColumn(complete_style="green"),
            TextColumn("[progress.percentage][light_slate_gray]{task.percentage:>3.1f}%"))

        progress_bar_id = progress_bar.add_task("", total=100)
        progress_bar.update(progress_bar_id, advance=1)

        text = Text(no_wrap=True, overflow="fold", style="light_slate_gray")
        text.stylize("bold magenta", 0, 6)
        _coltmp = Columns([progress_bar, text], equal=True)
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
        if self._is_running is True:
            return
        self._T = ThreadWithException(target=self._scan_orchestrator)
        self._T.start()
        self._T.join()

    def _scan_orchestrator(self):
        """
        Orchestrates the scanning process by starting individual port scans in separate threads.

        This method continuously checks for finished scans and removes them from the scan list.
        It then starts a new thread for each scan in the scan list and keeps track of the threads
        using a dictionary. The method waits for all scans to finish before exiting.

        Note: This method assumes the existence of the following instance variables:
        - _scan_list: A list of dictionaries representing the scans to be performed.
        - _scans_to_wait: A dictionary that maps scan names to thread objects and cancel events.
        - _is_running: A boolean flag indicating whether the orchestrator is running.

        Returns:
            None
        """
        self._scans_to_wait = {}

        self._is_running = True
        while True:
            self._remove_finished_scan_from_list()
            for _, _scan in enumerate(self._scan_list):
                _evt = Event()
                _thr = ThreadWithException(target=self._port_scan, args=(_scan["host"], _scan["profile"], _scan["name"], _evt,))
                _thr.start()

                for idx, _scan_s in enumerate(self._scan_list):
                    if _scan["name"] == _scan_s["name"]:
                        del self._scan_list[idx]
                        break
                self._scans_to_wait[str(_scan["name"])] = {"_thr": _thr, "_cancel_event": _evt}
                self._scans_history.append(str(_scan["name"]))
            time.sleep(0.1)

            if self.scans_to_wait == 0:
                time.sleep(0.2)

                if (self.scans_to_wait == 0 and (self._config.is_interactive is False and self._has_been_interactive is False)) or self._cleaning_up:
                    self._is_running = False
                    break

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
        """
        Retrieves the profile and its arguments from the store or a file.

        Args:
            _profile (str): The name of the profile to retrieve.

        Returns:
            tuple: A tuple containing the profile name and its arguments.
                   If the profile is not found in the store or file, returns (None, None).
        """
        try:
            profile = self.store.get_profile(_profile)
            profile_arguments = profile["arguments"]
        except StoreExceptions.DScanEntryNotFound:
            self.logger.error(f"Profile {_profile} not found in database")

        try:
            profile_from_file = self._load_profiles_from_file(self._config.conf_file)[_profile]
            self.store.save_profiles({_profile: profile_from_file})
            profile_arguments = profile_from_file["arguments"]
        except (KeyError, IOError) as e:
            self.logger.warning(f"Profile {_profile} neither in database or file: {str(e)}")
            return (None, None)
        return (_profile, profile_arguments)

    def _port_scan(self, __host=None, __profile=None, __name=None, __evt=None):
        """
        Perform a port scan using the specified profile and host.

        Returns:
            A list of the last n scans performed.

        Raises:
            AppExceptions.DScanInputValidationException: If the host format is invalid.
            AppExceptions.DScanSchemaException: If an error occurs during the scan.
        """
        _host = __host if __host is not None else self._config.host
        _profile = __profile if __profile is not None else self._config.profile
        _name = __name if __name is not None else f"scan-{_host}-{_profile}"

        _profile, _profile_arguments = self._get_profile(_profile)

        try:
            check_root_permissions()
        except PermissionError as e:
            self.logger.error(f"{str(e)}")
            os._exit(1)
        try:
            if validate_host(_host) is False:
                raise AppExceptions.DScanInputValidationException("Invalid host format")

            if self.ui_context is not None:
                self.ui_context["show_nmap_logs"] = self._config.is_interactive is False and self._has_been_interactive is False

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

            # getting the current date and time in order not to override existing files
            _now = datetime.now().strftime(FILE_DATE_FORMAT)
            # Create the report only if output_file is configured and has never got ininteractive mode
            if self._config.output_file is not None and (self._config.is_interactive is False and self._has_been_interactive is False):
                self._report_scans(last_n_scans, f"scans_{_host}_{_profile}_{_now}_{self._config.output_file}")

            self._result.append({
                "scans": last_n_scans,
                "date": _now,
                "host": _host,
                "profile": _profile,
                "finished": True
            })

            return last_n_scans
        except (ValueError, AppExceptions.DScanResultsSchemaException, ExporterExceptions.DScanExporterErrorProcessingData) as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanSchemaException(f"An error occurred during the scan: {str(e)}")

    def diffs(self, uuids=None):
        """
        Compares the scans for a given host within a specified date range.

        Returns:
            list: A list of scan differences.

        Raises:
            AppExceptions.DScanInputValidationException: If the date format is invalid.
            AppExceptions.DScanSchemaException: If the scan results schema is invalid.
            AppExceptions.DScanEntryNotFound: If no scan results are found for the specified host.
        """
        try:
            if datetime_validation(self._config.fdate) is False and uuids is None:
                raise AppExceptions.DScanInputValidationException(f"Invalid date format: {self._config.fdate}. Use format {APP_DATE_FORMAT}")

            scans = self.store.get_filtered_scans(
                uuid=uuids,
                host=self._config.host,
                last_n=self._config.n_scans,
                profile=self._config.profile,
                from_date=self._config.fdate,
                to_date=self._config.tdate
            )

            _split_scans_in_hosts = self.__split_scans_in_hosts([_s for _s in scans])

            diffs = self._list_scans_with_diffs([_s for _scans in _split_scans_in_hosts.values() for _s in _scans])
            if self._config.output_file is not None and (self._config.is_interactive is False and self._has_been_interactive is False):
                self._report_diffs(diffs, output_file=f"diffs_{self._config.output_file}")

            # getting the current date and time in order not to override existing files
            _now = datetime.now().strftime(FILE_DATE_FORMAT)
            self._result.append({
                "diffs": diffs,
                "date": _now,
                "finished": True
            })

            return diffs
        except StoreExceptions.DScanEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanEntryNotFound(F"Entry not found: {str(e)}")
        except AppExceptions.DScanResultsSchemaException as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanSchemaException(f"Invalid scan results schema: {str(e)}")

    @staticmethod
    def __split_scans_in_hosts(scans):
        """
        Splits a list of scans into a dictionary where the keys are the hosts and the values are lists of scans for each host.

        Args:
            scans (list): A list of scans.

        Returns:
            dict: A dictionary where the keys are the hosts and the values are lists of scans for each host.
        """
        _split_scans_in_hosts = {}
        for _s in scans:
            if _s["host"] not in _split_scans_in_hosts:
                _split_scans_in_hosts[_s["host"]] = []
            _split_scans_in_hosts[_s["host"]].append(_s)
        return _split_scans_in_hosts

    def files_diff(self, _diff_files=None):
        """
        Compare the results of multiple scan files and return the differences.

        Args:
            _diff_files (str): Comma-separated list of file paths to compare. If not provided, the method will use the
                               default diff files specified in the configuration.

        Returns:
            list: A list of dictionaries representing the differences between the scan results. Each dictionary contains the
                  following keys:
                  - "ids": A list of two integers representing the IDs of the compared scans.
                  - "uuids": A list of two strings representing the UUIDs of the compared scans.
                  - "generic": A list of two dictionaries representing the generic information of the compared scans. Each
                               dictionary contains the following keys:
                               - "host": The host name or IP address of the scan.
                               - "arguments": The arguments used for the scan.
                               - "profile_name": The name of the scan profile.
                  - "dates": A list of two strings representing the creation dates of the compared scans.
                  - "diffs": A dictionary representing the differences between the scan results.
                  - "result_hashes": A list of two strings representing the result hashes of the compared scans.

        Raises:
            AppExceptions.DScanInputValidationException: If less than two files are provided for comparison.
            AppExceptions.DScanInputValidationException: If a subnet is provided instead of a single host.
            AppExceptions.DScanInputValidationException: If more than one host is found in a single scan file.
        """
        if _diff_files is not None and _diff_files != "":
            _files = _diff_files.split(",")
        else:
            _files = self._config.diff_files.split(",")
        _imported_scans = []
        _importer = None
        if _files is None or len(_files) < 2:
            raise AppExceptions.DScanInputValidationException("At least two files must be provided to compare")
        for _f in _files:
            if _importer is None:
                _importer = Importer(self.store, _f, logger=self.logger)
                _r = _importer.load_results_from_file()
            else:
                _importer.filename = _f
                _r = _importer.load_results_from_file()

            _host = _r._nmaprun["args"].split(" ")[-1]
            _parsed = Parser.extract_port_scan_dict_results(_r)
            if "/" in _host:
                raise AppExceptions.DScanInputValidationException("Subnet is not supported for this operation")
            if len(_parsed) > 1:
                raise AppExceptions.DScanInputValidationException("Only one host per file is supported for this operation")

            _imported_scans.append(
                {
                    "created_at": datetime.fromtimestamp(int(
                        _r._runstats["finished"]["time"])).strftime(
                            APP_DATE_FORMAT) if "finished" in _r._runstats else None,
                    "results": _parsed[0],
                    "arguments": _r._nmaprun["args"]
                }
            )

        _final_diffs = []
        for i, _ in enumerate(_imported_scans, 1):
            if i == len(_imported_scans):
                break
            __diffs = self._diffs_between_dicts(
                self._results_to_port_dict(_imported_scans[i-1]["results"]),
                self._results_to_port_dict(_imported_scans[i]["results"]))
            _final_diffs.append({
                "ids": [0, 0],
                "uuids": ["", ""],
                "generic": [
                    {
                        "host": _imported_scans[i-1]["results"]["host"],
                        "arguments": _imported_scans[i-1]["arguments"],
                        "profile_name": ""
                    },
                    {
                        "host": _imported_scans[i]["results"]["host"],
                        "arguments": _imported_scans[i]["arguments"],
                        "profile_name": ""
                    }
                ],
                "dates": [
                    _imported_scans[i-1]["created_at"],
                    _imported_scans[i]["created_at"]],
                "diffs": __diffs,
                "result_hashes": ["", ""]
            })
        return _final_diffs

    def _list_scans_with_diffs(self, scans):
        """
        Returns a list of scans with differences between consecutive scans.

        Args:
            scans (list): A list of scan dictionaries.

        Returns:
            list: A list of dictionaries representing scans with differences.

        Raises:
            AppExceptions.DScanSchemaException: If the scan results have an invalid schema.
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
                                self._results_to_port_dict(scans[i-1]["results"]),
                                self._results_to_port_dict(scans[i]["results"])),
                            "result_hashes": [
                                scans[i-1]["result_hash"],
                                scans[i]["result_hash"]]
                        }
                    )
                except AppExceptions.DScanResultsSchemaException as e:
                    self.logger.error(f"{str(e)}")
                    raise AppExceptions.DScanSchemaException(f"Invalid scan results schema given to diffs method: {str(e)}")
        return scan_list_diffs

    def _results_to_port_dict(self, results):
        """
        Convert the scan results to a dictionary format.

        Args:
            results (dict): The scan results.

        Returns:
            dict: The converted port dictionary.

        Raises:
            AppExceptions.DScanResultsSchemaException: If the scan results have an invalid schema.
        """
        try:
            Scan().load(results)
        except (KeyError, ValidationError) as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanResultsSchemaException("Invalid scan results schema")

        port_dict = copy.deepcopy(results)

        port_dict["new_ports"] = {}
        for port in port_dict["ports"]:
            port_dict["new_ports"][port["portid"]] = port
        port_dict["ports"] = port_dict["new_ports"]
        del port_dict["new_ports"]

        return port_dict

    # ------------------------------------------------------------- DIFFS ------------------------------------------------------------- #

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

    # ------------------------------------------------------------- DIFFS END ------------------------------------------------------------- #

    def view(self):
        """
        Retrieves and filters scans based on the provided configuration.

        Returns:
            list: A list of filtered scans.

        Raises:
            AppExceptions.DScanInputValidationException: If the provided date format or port status type is invalid.
            AppExceptions.DScanEntryNotFound: If no scan results are found for the specified host.
        """
        try:
            if self._config.fdate is not None and datetime_validation(self._config.fdate) is False:
                raise AppExceptions.DScanInputValidationException(f"Invalid date format: {self._config.fdate}. Use format {APP_DATE_FORMAT}")

            if self._config.port_type is not None and validate_port_state_type(self._config.port_type.split(",")) is False:
                raise AppExceptions.DScanInputValidationException(f"Invalid port status type: {self._config.port_type}")

            scans = self.store.get_filtered_scans(
                    host=self._config.host,
                    last_n=self._config.n_scans,
                    profile=self._config.profile,
                    to_date=self._config.tdate,
                    from_date=self._config.fdate,
                    pstate=self._config.port_type)
            if self._config.output_file is not None:
                self._report_scans(scans, output_file=f"scans_{self._config.output_file}")

            return scans
        except StoreExceptions.DScanEntryNotFound as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanEntryNotFound(f"No scan results found for host {self._config.host}")

    def import_data(self, __filename=None):
        """
        Imports data from a file specified in the configuration.

        Returns:
            The imported data.

        Raises:
            AppExceptions.DScanImportError: If the method is not implemented.
        """
        _filename = __filename if __filename is not None else self._config.import_file
        try:
            _importer = Importer(self.store, _filename, logger=self.logger)

            return _importer.import_data()
        except (ImporterExceptions.DScanImportError, FileNotFoundError, NotImplementedError) as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanImportError(f"File {_filename} not found")

    def _report_diffs(self, diffs, output_file=None):
        """
        Generate a diff report based on the provided diffs.

        Args:
            diffs (list): A list of diffs to be included in the report.
            output_file (str, optional): The output file path for the report. If not provided,
                the default output file specified in the configuration will be used.

        Raises:
            AppExceptions.DScanSchemaException: If the diffs schema is invalid.
            AppExceptions.DScanExportError: If the output file is not provided.

        """
        try:
            articulated_diffs = []
            for diff in diffs:
                articulated_diffs.append(
                    {
                        "date_from": diff["dates"][1],
                        "date_to": diff["dates"][0],
                        "diffs": Parser.diffs_to_output_format(diff),
                        "generic": diff["generic"],
                        "uuids": diff["uuids"],
                    }
                )
        except AppExceptions.DScanResultsSchemaException as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanSchemaException("Could not handle diffs schema.")

        if self._config.output_file is not None or output_file is not None:
            try:
                reporter = Exporter(
                    articulated_diffs,
                    self._config.output_file if output_file is None else output_file,
                    self._config.template_file,
                    single=self._config.single,
                    logger=self.logger,
                )
                reporter.export()
            except ExporterExceptions.DScanExporterFileExtensionNotSpecified as e:
                self.logger.error(f"{str(e)}")
                raise AppExceptions.DScanExportError(f"Filename error: {str(e)}")
        else:
            self.logger.error("File not provided. Diff report was not generated")
            raise AppExceptions.DScanExportError("File not provided. Diff report was not generated")

    def _report_scans(self, scans, output_file=None):
        """
        Generate a scan report based on the provided scans.

        Args:
            scans (list): A list of scan results.
            output_file (str, optional): The output file path for the scan report. Defaults to None.

        Raises:
            AppExceptions.DScanResultsSchemaException: If the scan results schema is invalid.
            AppExceptions.DScanExportError: If the output file is not provided.

        Returns:
            None
        """
        try:
            DBScan(many=True).load(scans)
        except (KeyError, ValidationError) as e:
            self.logger.error(f"{str(e)}")
            raise AppExceptions.DScanResultsSchemaException("Invalid scan results schema")
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
            except ExporterExceptions.DScanExporterFileExtensionNotSpecified as e:
                self.logger.error(f"{str(e)}")
                raise AppExceptions.DScanExportError(f"Filename error: {str(e)}")
        else:
            raise AppExceptions.DScanExportError("File not provided. Scan report was not generated")

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
                self._report_scans(_res["scans"], f"scans_{_res['host']}_{_res['profile']}_{_res['date']}_{self._config.output_file}")

            if _res["finished"] is True and "diffs" in _res and _res["diffs"] is not None and self._config.output_file is not None:
                self._report_diffs(_res["diffs"], f"diffs_{_res['date']}_{self._config.output_file}")

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
    def diff_files(self):
        return self._config.diff_files

    @diff_files.setter
    def diff_files(self, value):
        self._config.diff_files = value

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
        if self._config.is_interactive is True:
            self._has_been_interactive = True

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
