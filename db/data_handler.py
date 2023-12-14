from . import db_manager
import logging

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class DataHandler:
    def __init__(self):
        db_manager.initializeDatabase()

        if db_manager.getProfile("default") is None:
            db_manager.setProfile("default")

    def saveScan(self, scanData, args):
        # Remove runstats until implemented
        scanData.pop(0)

        scanListId = db_manager.setScanList("default", args)

        for host in scanData:
            try:
                db_manager.setScanResults(
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
        return db_manager.getScanList(profile)

    def getProfileList(self):
        return db_manager.getProfileList()

    def getScanResults(self, id):
        return db_manager.getScanResults(id)

    def getProfile(self, profile):
        return db_manager.getProfile(profile)
