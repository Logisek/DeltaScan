# DeltaScan - Network scanning tool 
#     Copyright (C) 2024 Logisek
# 
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>

from .db.manager import RDBMS
from .utils import hash_string
import json
import logging
import uuid
import os
from deltascan.core.exceptions import (StoreExceptions,
                                       DatabaseExceptions)
from deltascan.core.config import (DATABASE)
from deltascan.core.schemas import Scan
from deltascan.core.config import LOG_CONF
from marshmallow import ValidationError


class Store:
    """
    A class that handles data operations for the DeltaScan application.
    """
    def __init__(self, db_path="", logger=None):
        self.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        self.db_path = f"{db_path}{DATABASE}"

        if os.stat(self.db_path).st_uid == 0:
            raise StoreExceptions.DScanPermissionError(
                f"{self.db_path} file belongs to root. "
                 "Please change the owner to a non-root user or run as sudo.")

        self.rdbms = RDBMS(self.db_path, logger=self.logger)

    def save_scans(self, profile_name, host_with_subnet, scan_data, created_at=None):
        """
        Save the scan data to the database.

        Args:
            profile_name (str): The name of the profile.
            subnet (str): The subnet of the scan.
            scan_data (list): The list of scan data.
            created_at (datetime, optional): The creation timestamp. Defaults to None.

        Returns:
            list: The list of newly created scans.

        Raises:
            StoreExceptions.DScanInputSchemaError: If the scan data fails validation.
            StoreExceptions.DScanErrorCreatingEntry: If the scan data fails to save.
        """
        if scan_data is []:
            return None
        try:
            Scan(many=True).load(scan_data)
        except ValidationError as err:
            raise StoreExceptions.DScanInputSchemaError(str(err))

        _new_scans = []

        for idx, single_host_scan in enumerate(scan_data):
            try:
                _uuid = uuid.uuid4()
                json_scan_data = json.dumps(single_host_scan)
                single_host_scan["os"] = {"1": "unknown"} if len(
                    single_host_scan.get("os", {"1": "unknown"})) == 0 else single_host_scan.get("os", {"1": "unknown"})
                _n = self.rdbms.create_port_scan(
                    _uuid,
                    single_host_scan.get("host", "unknown"),
                    host_with_subnet,
                    single_host_scan.get("os", {})["1"],
                    profile_name,
                    json_scan_data,
                    hash_string(json_scan_data),
                    None,
                    created_at=created_at
                )
                _new_scans.append(_n)
            except DatabaseExceptions.DScanRDBMSErrorCreatingEntry as e:
                # TODO: Propagating the same exception until higher level until finding another way to handle it
                self.logger.error("Error saving scan data: %s. "
                                  "Stopped on index %s", str(e), idx)
                raise StoreExceptions.DScanErrorCreatingEntry(str(e))
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
                new_item_id = self.rdbms.create_profile(
                    profile_name,
                    profile_values["arguments"]
                )
                return new_item_id
            except DatabaseExceptions.DScanRDBMSErrorCreatingEntry as e:
                # TODO: Propagating the same exception until higher level until finding another way to handle it
                self.logger.error("Error saving profile: %s", str(e))
                raise StoreExceptions.DScanErrorCreatingEntry(str(e))

    def get_filtered_scans(self, uuid=None, host=None, last_n=20, profile=None, from_date=None, to_date=None, pstate="all"):
        """
        Retrieves a list of filtered scans based on the provided parameters.

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
            return [
                self._filter_results_and_transform_results_to_dict(scan, pstate)
                for scan in self.rdbms.get_scans(uuid, host, last_n, profile, from_date, to_date)
            ]
        except DatabaseExceptions.DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving scan list: %s", str(e))
            raise StoreExceptions.DScanEntryNotFound(str(e))

    def get_scans_count(self):
        """
        Retrieves the count of scans stored in the database.

        Returns:
        int: The count of scans.

        Raises:
        DScanRDBMSEntryNotFound: If the scan count retrieval fails.
        """
        try:
            return self.rdbms.get_scans_count()
        except DatabaseExceptions.DScanRDBMSEntryNotFound as e:
            self.logger.error("Error retrieving scan count: %s", str(e))
            raise StoreExceptions.DScanEntryNotFound(str(e))

    def get_profiles_count(self):
        """
        Retrieves the count of profiles stored in the database.

        Returns:
        int: The count of profiles.

        Raises:
        DScanRDBMSEntryNotFound: If the profile count retrieval fails.
        """
        try:
            return self.rdbms.get_profiles_count()
        except DatabaseExceptions.DScanRDBMSEntryNotFound as e:
            self.logger.error("Error retrieving profile count: %s", str(e))
            raise StoreExceptions.DScanEntryNotFound(str(e))

    def get_profile(self, profile_name):
        """
        Retrieves the profile from the database.

        Parameters:
        - profile_name: The profile to retrieve.

        Returns:
        The profile.
        """
        try:
            return self.rdbms.get_profile(
                profile_name)
        except DatabaseExceptions.DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving profile: %s", str(e))
            raise StoreExceptions.DScanEntryNotFound(str(e))

    def get_profiles(self, profile_name=None):
        """
        Retrieves the profile from the database.

        Parameters:
        - profile_name: The profile to retrieve.

        Returns:
        The profile.
        """
        try:
            return list(self.rdbms.get_profiles(profile_name))
        except DatabaseExceptions.DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            self.logger.error("Error retrieving profiles: %s", str(e))
            raise StoreExceptions.DScanEntryNotFound(str(e))

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
        if "all" not in state_type and len(scan["results"]["ports"]) > 0:
            scan["results"]["ports"] = [r for r in scan["results"]["ports"] if r["state"]["state"] in state_type]
        return scan
