from .db import manager as db
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
        store = db.init()

    def save(self, scanData, args):
        """
        Saves the scan data to the database.

        Parameters:
        - scanData: The scan data to be saved.
        - args: Additional arguments for the scan.

        Returns:
        None
        """
        # Remove runstats until implemented
        scanData.pop(0)

        scanListId = manager.setScanList("default", args)

        for host in scanData:
            try:
                manager.setScanResults(
                    scanListId,
                    host.get("address", "unknown"),
                    host.get("os", "unknown"),
                    host.get("ports", "unknown"),
                    host.get("status", "unknown"),
                )

            except Exception as e:
                logging.error("Error saving scan data: %s", str(e))
                return

        return

    def getScanList(self, profile="default"):
        """
        Retrieves the scan list from the database.

        Parameters:
        - profile: The profile to retrieve the scan list for. Default is "default".

        Returns:
        The scan list.
        """
        return manager.getScanList(profile)

    def getProfileList(self):
        """
        Retrieves the profile list from the database.

        Returns:
        The profile list.
        """
        return manager.getProfileList()

    def getScanResults(self, id):
        """
        Retrieves the scan results from the database.

        Parameters:
        - id: The ID of the scan.

        Returns:
        The scan results.
        """
        return manager.getScanResults(id)

    def getProfile(self, profile):
        """
        Retrieves the profile from the database.

        Parameters:
        - profile: The profile to retrieve.

        Returns:
        The profile.
        """
        return manager.getProfile(profile)
