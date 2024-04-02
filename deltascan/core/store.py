from .db.manager import RDBMS
from .utils import hash_string
import json 
import logging
import uuid
from deltascan.core.exceptions import (DScanRDBMSEntryNotFound,
                                       DScanRDBMSErrorCreatingEntry)
from deltascan.core.schemas import Scan
from deltascan.core.exceptions import DScanResultsSchemaException
from deltascan.core.config import LOG_CONF

from marshmallow  import ValidationError



class Store:
    """
    A class that handles data operations for the DeltaScan application.

    Methods:
    - __init__(): Initializes the DataHandler object and initializes the database.
    - saveScan(scanData, args): Saves the scan data to the database.
    - getScanList(profile="default"): Retrieves the scan list from the database.
    - getProfileList(): Retrieves the profile list from the database.
    - getScanResults(id): Retrieves the scan results from the database.
    - getProfile(profile): Retrieves the profile from the database.
    """
    def __init__(self, logger=None):
        self.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        self.store = RDBMS(logger=self.logger)

    def save_scans(self, profile_name, subnet, scan_data, profile_arguments, created_at=None):
        """
        Saves the scan data to the database.

        Parameters:
        - scan_data: The scan data to be saved.
        - args: Additional arguments for the scan.

        Returns:
        None
        """
        try:
            Scan(many=True).load(scan_data)
        except ValidationError as err:
            raise DScanResultsSchemaException(str(err))

        _new_scans = []

        for idx, single_host_scan in enumerate(scan_data):
            try:
                _uuid = uuid.uuid4()
                json_scan_data = json.dumps(single_host_scan)
                single_host_scan["os"] = ["none"] if len(single_host_scan.get("os", [])) == 0 else single_host_scan.get("os", [])
                _n = self.store.create_port_scan(
                    _uuid,
                    single_host_scan.get("host", "none") + subnet,
                    single_host_scan.get("os", [])[0],
                    profile_name,
                    json_scan_data,
                    hash_string(json_scan_data),
                    None,
                    created_at=created_at
                )
                self.logger.info("Saved scan data for host %s", 
                             single_host_scan.get("host", "none"))
                _new_scans.append(_n)
            except DScanRDBMSErrorCreatingEntry as e:
                # TODO: Propagating the same exception until higher level until finding another way to handle it
                self.logger.error("Error saving scan data: %s. "
                              "Stopped on index %s", str(e), idx)
                raise DScanRDBMSErrorCreatingEntry(str(e))
        return _new_scans
    
    def save_profiles(self, profiles):
        """
        Saves the profile to the database.

        Parameters:
        - profile: The profile to be saved.

        Returns:
        None
        """
        for profile_name, profile_values in profiles.items():
            try:
                new_item_id = self.store.create_profile(
                    profile_name,
                    profile_values["arguments"]
                )
                self.logger.info("Saved profile %s", 
                             profile_name)
                return new_item_id
            except DScanRDBMSErrorCreatingEntry as e:
                # TODO: Propagating the same exception until higher level until finding another way to handle it
                self.logger.error("Error saving profile: %s", str(e))
                raise DScanRDBMSErrorCreatingEntry(str(e))

    def get_filtered_scans(self, uuid=None, host=None, last_n=20, profile=None, from_date=None, to_date=None, pstate="all"):
        """
        Retrieve a list of filtered scans based on the provided parameters.

        Args:
            uuid (str, optional): The UUID of the scan. Defaults to None.
            host (str, optional): The host of the scan. Defaults to None.
            last_n (int, optional): The number of latest scans to retrieve. Defaults to 20.
            profile (str, optional): The profile of the scan. Defaults to None.
            from_date (str, optional): The start date of the scan. Defaults to None.
            to_date (str, optional): The end date of the scan. Defaults to None.
            pstate (str, optional): The state of the scan. Defaults to "all".

        Returns:
            list: A list of filtered scans, where each scan is transformed into a dictionary.

        Raises:
            DScanRDBMSEntryNotFound: If the scan list retrieval fails.
        """
        try:
            return [self._filter_results_and_transform_results_to_dict(scan, pstate) for scan in self.store.get_scans(uuid, host, last_n, profile, from_date, to_date)]
        except DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving scan list: %s", str(e))
            raise DScanRDBMSEntryNotFound(str(e))
            
    def get_last_n_scans_for_host(self, host, last_n, profile, uuid=None, from_date=None, to_date=None, ): # TODO: probably delete this method and use get_filtered_scans instead
        """
        Retrieves the scan list from the database.

        Parameters:
        - profile: The profile to retrieve the scan list for. Default is "default".

        Returns:
        The scan list.
        """
        try:
            return [self._results_to_dict(scan) for scan in self.store.get_scans(uuid, host, last_n, profile, from_date, to_date)]
        except DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving scan list: %s", str(e))
            raise DScanRDBMSEntryNotFound(str(e))

    def get_profile(self, profile_name):
        """
        Retrieves the profile from the database.

        Parameters:
        - profile: The profile to retrieve.

        Returns:
        The profile.
        """
        try:
            return self.store.get_profile(
                profile_name)
        except DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving profile: %s", str(e))
            raise DScanRDBMSEntryNotFound(str(e))

    def get_profiles(self, profile_name=None):
        """
        Retrieves the profile from the database.

        Parameters:
        - profile: The profile to retrieve.

        Returns:
        The profile.
        """
        try:
            return list(self.store.get_profiles(profile_name))
        except DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving profiles: %s", str(e))
            raise DScanRDBMSEntryNotFound(str(e))

    @staticmethod
    def _results_to_dict(scan):
        """
        Converts the scan to a dictionary.

        Parameters:
        - scan: The scan to convert.

        Returns:
        The scan as a dictionary.
        """
        scan["results"] = json.loads(scan["results"])
        return scan

    @staticmethod
    def _filter_results_and_transform_results_to_dict(scan, state_type="all"):
        """
        Filters the port status types.

        Parameters:
        - scan: The scan to filter.
        - scan_results: The scan results to filter.

        Returns:
        The filtered scan results.
        """
        scan["results"] = json.loads(scan["results"])
        if "all" not in state_type:
            scan["results"]["ports"] = [r for r in scan["results"]["ports"] if r["state"]["state"] in state_type]
        return scan