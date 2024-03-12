from .db.manager import RDBMS
from .utils import hash_json
import json 
import logging
from deltascan.core.exceptions import (DScanRDBMSEntryNotFound,
                                       DScanRDBMSErrorCreatingEntry)

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

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
    def __init__(self):
        self.store = RDBMS()

    def save_scans(self, profile_name, subnet, scan_data, profile_arguments):
        """
        Saves the scan data to the database.

        Parameters:
        - scan_data: The scan data to be saved.
        - args: Additional arguments for the scan.

        Returns:
        None
        """
        for idx, single_host_scan in enumerate(scan_data):
            try:
                json_scan_data = json.dumps(single_host_scan)
                new_id = self.store.create_port_scan(
                    single_host_scan.get("host", "unknown") + subnet,
                    single_host_scan.get("os", "unknown"),
                    profile_name,
                    json_scan_data,
                    hash_json(json_scan_data),
                    None
                )
                logging.info("Saved scan data for host %s", 
                             single_host_scan.get("host", "unknown"))
            except DScanRDBMSErrorCreatingEntry as e:
                # TODO: Propagating the same exception until higher level until finding another way to handle it
                logging.error("Error saving scan data: %s. "
                              "Stopped on index %s", str(e), idx)
                raise DScanRDBMSErrorCreatingEntry(str(e))
    
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
                logging.info("Saved profile %s", 
                             profile_name)
                return new_item_id
            except DScanRDBMSErrorCreatingEntry as e:
                # TODO: Propagating the same exception until higher level until finding another way to handle it
                logging.error("Error saving profile: %s", str(e))
                raise DScanRDBMSErrorCreatingEntry(str(e))

    def get_filtered_scans(self, host="", last_n=20, profile="", creation_date=None):
        """
        Retrieves the scan list from the database.

        Parameters:
        - profile: The profile to retrieve the scan list for. Default is "default".

        Returns:
        The scan list.
        """
        try:
            return self.store.get_scans(host, last_n, profile, creation_date)
        except DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            logging.error("Error retrieving scan list: %s", str(e))
            raise DScanRDBMSEntryNotFound(str(e))\
            
    def get_last_n_scans_for_host(self, host, last_n, profile, creation_date=None):
        """
        Retrieves the scan list from the database.

        Parameters:
        - profile: The profile to retrieve the scan list for. Default is "default".

        Returns:
        The scan list.
        """
        try:
            return self.store.get_scans(host, last_n, profile, creation_date)
        except DScanRDBMSEntryNotFound as e:
            # TODO: Propagating the same exception until higher level until finding another way to handle it
            logging.error("Error retrieving scan list: %s", str(e))
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
            logging.error("Error retrieving profile: %s", str(e))
            raise DScanRDBMSEntryNotFound(str(e))
