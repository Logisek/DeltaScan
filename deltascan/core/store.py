from .db.manager import RDBMS
from .utils import hash_json
import json 
import logging

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

    def save_scans(self, profile, subnet, scan_data, args):
        """
        Saves the scan data to the database.

        Parameters:
        - scan_data: The scan data to be saved.
        - args: Additional arguments for the scan.

        Returns:
        None
        """
        for single_host_scan in scan_data:
            try:
                json_scan_data = json.dumps(single_host_scan)
                _ = self.store.create_port_scan(
                    single_host_scan.get("host", "unknown") + subnet,
                    single_host_scan.get("os", "unknown"),
                    profile,
                    json_scan_data,
                    hash_json(json_scan_data),
                    None
                )

            except Exception as e:
                logging.error("Error saving scan data: %s", str(e))
                return

        return
    
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
                _ = self.store.create_profile(
                    profile_name,
                    profile_values["arguments"]
                )

            except Exception as e:
                logging.error("Error saving profile: %s", str(e))
                return

        return

    def get_last_n_scans_for_host(self, host, last_n, creation_date=None):
        """
        Retrieves the scan list from the database.

        Parameters:
        - profile: The profile to retrieve the scan list for. Default is "default".

        Returns:
        The scan list.
        """
        return self.store.get_scans(host, last_n, creation_date)

    def get_profile(self, profile_name):
        """
        Retrieves the profile from the database.

        Parameters:
        - profile: The profile to retrieve.

        Returns:
        The profile.
        """
        return self.store.get_profile(
            profile_name)
